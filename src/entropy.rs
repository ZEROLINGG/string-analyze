//! 文本与字节序列的熵值 (Entropy) 计算模块。
//!
//! 本模块提供基于信息论的多种熵计算方法（基础香农熵、差分熵、二元语法熵），
//! 并提供了一个融合这三种特征的复合熵评分系统，
//! 专门用于评估文本的随机程度，以辅助过滤无效匹配并精准定位高随机性的密钥、Token 或混淆代码。

use std::cell::RefCell;

/// 计算给定频率分布的香农熵 (Shannon Entropy) 核心算法。
///
/// 内部公式基于 `H = -Σ (p_i * log2(p_i))`，其中 `p_i = count / total`。
/// 为了优化计算性能，对公式进行了代数变形：
/// `H = log2(total) - (Σ (count * log2(count)) / total)`
/// 这样可以避免在循环内部进行除法运算。
#[inline(always)]
fn calc_entropy<'a, I>(counts: I, total_grams: f64) -> f64
where
    I: Iterator<Item = &'a u32>,
{
    let sum_c_log2_c: f64 = counts
        .filter(|&&c| c > 0)
        .map(|&c| {
            let c_f64 = c as f64;
            c_f64 * c_f64.log2()
        })
        .sum();
    total_grams.log2() - (sum_c_log2_c / total_grams)
}

/// 计算标准的单字节香农熵 (1-gram Entropy)。
///
/// 评估输入序列中各个字节（0-255）出现的均匀程度。
/// 返回值区间通常为 `[0.0, 8.0]` (因为 2^8 = 256)。
///
/// # 参数
/// - `bytes`: 待计算的字节切片。
pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    calc_entropy(counts.iter(), bytes.len() as f64)
}

/// 计算差分熵 (Delta Entropy)。
///
/// 评估相邻字节之间**差值**的分布均匀度。
///
/// # 作用
/// 标准熵无法识破规律递增或递减的序列（如 `"12345678"` 或 `"abcdefgh"`），
/// 这些序列在单字节熵中表现为高熵，但在差分熵计算中，由于差值总是固定值（如 `1`），
/// 其差分熵会极其接近 `0.0`，从而有效过滤掉这批伪随机字符串。
pub fn delta_entropy(bytes: &[u8]) -> f64 {
    let len = bytes.len();

    if len < 2 {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for window in bytes.windows(2) {
        let delta = window[1].wrapping_sub(window[0]);
        counts[delta as usize] += 1;
    }

    calc_entropy(counts.iter(), (len - 1) as f64)
}

/// 计算二元语法熵 (2-gram / Bigram Entropy)。
///
/// 评估相邻两个字节组合（0x0000 - 0xFFFF，共 65536 种可能）的分布情况。
/// 理论最大值为 `16.0` (2^16)。用于评估序列中字符组合的复杂度和随机性。
///
/// # 性能优化
/// 因为需要 `65536` 大小的数组，频繁的堆内存分配 (`Vec::new`) 会严重拖慢性能。
/// 此处使用了 `thread_local!` 缓存复用的方式，使得并发扫描时零内存分配。
pub fn gram_entropy2(bytes: &[u8]) -> f64 {
    thread_local! {
        // 使用 (counts, visited_indices) 的组合来实现 O(K) 的快速清零 (K 为独立 2-gram 数量)
        static GRAM_BUFFER: RefCell<(Vec<u32>, Vec<u16>)> = RefCell::new((vec![0; 65536], Vec::with_capacity(4096)));
    }
    let len = bytes.len();

    if len < 2 {
        return 0.0;
    }

    GRAM_BUFFER.with(|buf| {
        let (counts, visited) = &mut *buf.borrow_mut();
        let total_grams = (len - 1) as f64;

        for w in bytes.windows(2) {
            let idx = ((w[0] as usize) << 8) | (w[1] as usize);
            if counts[idx] == 0 {
                visited.push(idx as u16);
            }
            counts[idx] += 1;
        }

        let mut sum_c_log2_c = 0.0;
        for &idx in visited.iter() {
            let u_idx = idx as usize;
            let c = counts[u_idx];
            counts[u_idx] = 0; // 顺手清理数组，为下一次调用做准备

            let c_f64 = c as f64;
            sum_c_log2_c += c_f64 * c_f64.log2();
        }

        visited.clear();

        total_grams.log2() - (sum_c_log2_c / total_grams)
    })
}

/// 计算综合复合熵 (Composite Entropy) 评分。
///
/// 融合了标准熵、差分熵和二元语法熵，输出一个归一化到 `[0.0, 10.0]` 的综合评分。
/// 分数越高，表示序列越趋近于真正的强随机（如高质量哈希、密码、加密密钥）。
///
/// # 算法逻辑
/// 1. 提取三种熵并归一化到 `[0.0, 1.0]` 的区间。
/// 2. 对 2-gram 熵 (`n3`) 应用一个平滑多项式 `y = -4x^5 + 15x^4 - 20x^3 + 10x^2`，
///    这是一种基于 Smoothstep 思想的映射，旨在压制处于中低水平的 2-gram 影响。
/// 3. 采用**带有负指数 (`P = -1.6`) 的加权幂平均法** (Weighted Power Mean) 融合三者。
///    负指数的特性是具有**“木桶效应 / 惩罚低分”**：只要三种熵中有任意一个明显偏低（例如具有规律性递增），
///    整体的分数就会被大幅拉低。
pub fn composite_entropy(bytes: &[u8]) -> f64 {
    let len = bytes.len();
    if len < 4 {
        return 0.0;
    }

    let e1 = entropy(bytes);
    let e2 = delta_entropy(bytes);
    let e3 = gram_entropy2(bytes);

    const EPS: f64 = 1e-6;
    let n1 = (e1 / 8.0).clamp(EPS, 1.0);
    let n2 = (e2 / 8.0).clamp(EPS, 1.0);

    let n3_raw = (e3 / 16.0).clamp(EPS, 1.0);

    // 对 2-gram 应用多项式非线性映射 y = -4x^5 + 15x^4 - 20x^3 + 10x^2
    let n3 = {
        let x = n3_raw;
        (x * x * (10.0 + x * (-20.0 + x * (15.0 - 4.0 * x)))).clamp(EPS, 1.0)
    };

    // 权重配置
    const W1: f64 = 0.6; // 基础熵占主导
    const W2: f64 = 0.3; // 差分熵
    const W3: f64 = 0.1; // 2-gram 熵
    const P: f64 = -1.6; // 幂指数，负值强调惩罚偏低的特征值

    // 计算加权幂平均
    let mean_pow = W1 * n1.powf(P) + W2 * n2.powf(P) + W3 * n3.powf(P);
    let combined = mean_pow.powf(1.0 / P);

    (combined * 10.0).clamp(0.0, 10.0)
}



#[cfg(test)]
mod tests {
    use rand::{random, rng, RngExt};
    use super::*;

    #[test]
    fn test_entropy() {
        let input = &[
            "unittests src/lib.rs (target/debug/deps/string_analyze-551ebe6d3e6cc1ac)",
            "0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef",
            "96ef6443c6effd748c7202c04f0577f92761b821db19fdfea2a5c2364b439209",
            "horizontal-scroll-mode",
            "112233445566778899aabbccddeeffxxyyzz112233445566778899aabbccddeeffxxyyzz",
            "aGVsbG8=",
            "MDEyMzQ1Njc4OUFNREV5TXpRMU5qYzRPVUZDUTBSRlJqQXhNak09QkNERUYwMTIz",
            "mTyqm7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI==",
            "12~3",
            "1[82~3",
            " ",
            "ccVoejdMVQnfrzpgIunpQchW6WXcCnuX7leuRhzY3Ripc26KwOtCqxBRcjmHbN9PiaesCgHTi9iF",
            r#"M_2cL`Eqq:;|z_hiRTvhW@RLyq&d+UPXf6$ZarHI+9AiM[ZcQ"8egZ4m3Ur>J*AJE>kitQ@5Exo!C3$z.c[E#{*Rq5D"#,
            "豫章故郡，洪都新府。星分翼軫，地接衡廬。襟三江而帶五湖，控蠻荊而引甌越。物華天寶，龍光射牛斗之墟；人傑地靈，徐孺下陳蕃之榻。雄州霧列，俊彩星馳。臺隍枕夷夏之交，賓主盡東南之美。都督閻公之雅望，棨戟遙臨；宇文新州之懿範，襜帷暫駐。十旬休假，勝友如雲。千里逢迎，高朋滿座。騰蛟起鳳，孟學士之詞宗；紫電青霜，王將軍之武庫。家君作宰，路出名區。童子何知？躬逢勝餞。",
        ];

        for s in input {
            println!("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            println!("[entropy          ] [{:<5.3}]\t{s:.128}", entropy(s.as_bytes()));
            println!("[delta_entropy    ] [{:<5.3}]\t{s:.128}", delta_entropy(s.as_bytes()));
            println!("[gram_entropy2    ] [{:<5.3}]\t{s:.128}", gram_entropy2(s.as_bytes()));
            println!("[composite_entropy] [{:<5.3}]\t{s:.128}", composite_entropy(s.as_bytes()));
        }
        let input = &mut vec![
            b"\xd6\x23\x15\x9e\xbd\xe2\x90\xf9\xaa\xa0\x2e\xa0\x80\x9a\xa6\xf3\xcd\x31\xaa\x0d\x04\x6f\x51\x9c\xf1\x34\xcd\xef\x41\x29\xa4\x28\x44\x0c\xf7\x2d\xbb\x3d\x69\xf2\x03\xff\x9d\x54\x95\x25\x2d\x83\xd2\x80\x8d\x44\xef\xef\xf5\x6a\xf8\xc3\x61\x99\x9c\xe9\x2c\xec\x23\x3b\xea\xf3\x43\x1f\x57\xbd\x45\xce\x0e\x96\x4c\xb7\xbf\x28\x08\x16\x77\x53\x83\x59\x16\xd3\xac".as_slice()
        ];
        let x256 = random::<[u8;256]>();
        input.push(x256.as_slice());
        let x512 = random::<[u8;512]>();
        input.push(x512.as_slice());

        let x1024 = random::<[u8;1024]>();
        input.push(x1024.as_slice());

        let mut x4096 = vec![0u8;4096];
        rng().fill(&mut x4096);
        input.push(x4096.as_slice());

        for b in input {
            println!("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
            println!("[entropy          ] [{:<5.3}]\t{:.128}", entropy(b), format!("{b:?}"));
            println!("[delta_entropy    ] [{:<5.3}]\t{:.128}", delta_entropy(b), format!("{b:?}"));
            println!("[gram_entropy2    ] [{:<5.3}]\t{:.128}", gram_entropy2(b), format!("{b:?}"));
            println!("[composite_entropy] [{:<5.3}]\t{:.128}", composite_entropy(b), format!("{b:?}"));
        }
    }
}