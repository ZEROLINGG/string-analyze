//! 字符串匹配与启发式特征分析工具模块。
//!
//! 本模块提供了底层的高性能字符串搜索算法（子串、字符集、正则），
//! 以及针对特定编码（如 Base64、Hex）的启发式（Heuristics）校验函数。
//! 这些工具被广泛应用于扫描规则的执行流中。

#![allow(unused)]
use crate::State;
use regex::Regex;

/// 匹配目标抽象特征。
///
/// 允许底层匹配函数（如 `has_keyword`）既可以作为一个单纯的布尔检查器（传入 `&str`），
/// 也可以作为一个范围捕获器（传入 `&mut State`），从而避免重复编写匹配逻辑。
pub trait MatchTarget<'a> {
    /// 获取当前正在处理的完整字符串。
    fn get_input(&self) -> &'a str;
    /// 清空之前记录的所有匹配区间。
    fn clear_ranges(&mut self);
    /// 记录一个新的命中区间 `[start, end)`。
    fn push_range(&mut self, start: usize, end: usize);
}

// 针对只读字符串的空实现（仅用于布尔判断，丢弃捕获的区间）
impl<'a> MatchTarget<'a> for &'a str {
    #[inline]
    fn get_input(&self) -> &'a str {
        *self
    }
    #[inline]
    fn clear_ranges(&mut self) {}
    #[inline]
    fn push_range(&mut self, _start: usize, _end: usize) {}
}

// 针对规则状态的实现（会将匹配到的区间真实记录到 State 中）
impl<'a, 'b> MatchTarget<'a> for &'b mut State<'a> {
    #[inline]
    fn get_input(&self) -> &'a str {
        self.input
    }
    #[inline]
    fn clear_ranges(&mut self) {
        self.ranges.clear();
    }
    #[inline]
    fn push_range(&mut self, start: usize, end: usize) {
        self.ranges.push((start, end));
    }
}

/// 扫描输入文本是否包含指定的子串关键词。
///
/// 匹配到的所有位置会被写入 `target`。
///
/// # 参数
/// - `target`: 匹配目标载体（`&str` 或 `&mut State`）。
/// - `keyword`: 要查找的子串。
/// - `ignore_case`: 是否忽略大小写（仅支持 ASCII 忽略大小写，以保证性能）。
#[inline]
pub fn has_keyword<'a>(mut target: impl MatchTarget<'a>, keyword: &str, ignore_case: bool) -> bool {
    target.clear_ranges();
    let input = target.get_input();
    let k_len = keyword.len();
    if k_len == 0 || input.len() < k_len {
        return false;
    }

    let mut found = false;

    if !ignore_case {
        let mut start = 0;
        while let Some(idx) = input[start..].find(keyword) {
            let abs_idx = start + idx;
            target.push_range(abs_idx, abs_idx + k_len);
            found = true;
            start = abs_idx + k_len;
        }
    } else {
        // 忽略大小写模式，采用 ASCII 窗口滑动匹配
        let input_bytes = input.as_bytes();
        let keyword_bytes = keyword.as_bytes();
        let mut i = 0;
        while i <= input_bytes.len() - k_len {
            let window = &input_bytes[i..i + k_len];
            if window.eq_ignore_ascii_case(keyword_bytes) {
                // 确保匹配边界在有效的 UTF-8 字符上
                if input.is_char_boundary(i) && input.is_char_boundary(i + k_len) {
                    target.push_range(i, i + k_len);
                    found = true;
                }
                i += k_len;
            } else {
                i += 1;
            }
        }
    }
    found
}

/// 扫描输入文本是否包含指定的字符集合。
///
/// # 参数
/// - `chars`: 需要查找的字符数组。
/// - `any`: 如果为 `true`，只要出现 `chars` 中的任意一个字符即算匹配成功；
///          如果为 `false`，则必须包含 `chars` 中的**所有**不同字符才算成功。
/// - `ignore_case`: 是否忽略 ASCII 大小写。
#[inline]
pub fn has_chars<'a>(
    mut target: impl MatchTarget<'a>,
    chars: &[char],
    any: bool,
    ignore_case: bool,
) -> bool {
    target.clear_ranges();
    let input = target.get_input();

    if chars.is_empty() || input.is_empty() {
        return false;
    }

    let mut target_map = [false; 256];
    let mut target_count = 0;

    // 1. 构建目标字符掩码表 (仅支持 ASCII)
    for &c in chars {
        if c.is_ascii() {
            let b = if ignore_case {
                c.to_ascii_lowercase() as usize
            } else {
                c as usize
            };
            if !target_map[b] {
                target_map[b] = true;
                target_count += 1; // 统计有多少种独立的目标字符
            }
        }
    }

    if target_count == 0 {
        return false;
    }

    let mut found_map = [false; 256];
    let mut distinct_found = 0;
    let mut any_found = false;

    // 2. 扫描输入字符串并记录命中的单字节位置
    for (i, b) in input.bytes().enumerate() {
        if !b.is_ascii() {
            continue;
        }
        let val = if ignore_case {
            b.to_ascii_lowercase() as usize
        } else {
            b as usize
        };

        if target_map[val] {
            // 标记当前命中字符的区间
            target.push_range(i, i + 1);
            any_found = true;

            // 如果要求包含所有指定字符 (!any)，需记录当前找到了几种独立字符
            if !any && !found_map[val] {
                found_map[val] = true;
                distinct_found += 1;
            }
        }
    }

    // 3. 校验最终结果
    if any {
        any_found
    } else {
        let all_found = distinct_found == target_count;
        if !all_found {
            // 如果没有找齐所有指定的字符，视为失败，清空捕获区间
            target.clear_ranges();
        }
        all_found
    }
}

/// 执行正则表达式扫描，将所有命中区间记录进目标载体。
#[inline]
pub fn has_regex<'a>(mut target: impl MatchTarget<'a>, re: &Regex) -> bool {
    target.clear_ranges();
    let input = target.get_input();
    let mut found = false;

    for mat in re.find_iter(input) {
        target.push_range(mat.start(), mat.end());
        found = true;
    }
    found
}

/// 计算字符串中大写字母占所有字母（大小写）的比例。
///
/// 忽略非字母字符。如果字符串没有英文字母，返回 `0.0`。
#[inline]
pub fn upper_prob(input: &str) -> f64 {
    let mut upper_count = 0;
    let mut letter_count = 0;

    for b in input.bytes() {
        if b.is_ascii_uppercase() {
            upper_count += 1;
            letter_count += 1;
        } else if b.is_ascii_lowercase() {
            letter_count += 1;
        }
    }

    if letter_count == 0 {
        return 0.0;
    }
    (upper_count as f64) / (letter_count as f64)
}

/// 快速检查字符串是否包含 ASCII 大写字母。
#[inline]
pub fn has_upper(input: &str) -> bool {
    input.bytes().any(|b| b.is_ascii_uppercase())
}

/// 快速检查字符串是否包含 ASCII 小写字母。
#[inline]
pub fn has_lower(input: &str) -> bool {
    input.bytes().any(|b| b.is_ascii_lowercase())
}

/// 启发式判断字符串是否可能是一段真实的 Base64 编码数据。
///
/// 旨在过滤掉碰巧符合 Base64 字符集范围的普通英语长句或纯数字。
///
/// # 过滤规则 (Heuristics)
/// 1. **长度限制**: 必须大于 8 个字符。
/// 2. **填充符校验**: `=` 最多出现 2 次。
/// 3. **非法结尾**: 有效载荷（去除 `=` 后）不能以 `/` 或 `+` 结尾。
/// 4. **字节对齐**: 总长度必须是 4 的倍数。
/// 5. **混入度校验**: 必须包含数字或特殊字符（`+`, `/`, `=`），防止将纯字母当成 Base64。
/// 6. **大小写比例**: 大写字母在总字母中的比例必须介于 `0.2` 到 `0.8` 之间（真实的 Base64 大小写分布往往较为均匀）。
/// 7. **大小写共存**: 必须同时包含大写和小写字母。
pub fn is_base64(s: &str) -> bool {
    let len = s.len();

    // 1. 长度检查：至少4个字符，出于降噪目的要求大于 8
    if len <= 8 {
        return false;
    }

    // 2. 去除填充符并检查
    let trimmed = s.trim_end_matches('=');
    let padding_count = len - trimmed.len();

    // 填充符只能是0, 1, 或2个
    if padding_count > 2 {
        return false;
    }

    // 3. Base64 有效载荷不能以 / 或 + 结尾
    if trimmed.ends_with('/') || trimmed.ends_with('+') {
        return false;
    }
    if len % 4 != 0 {
        return false;
    }

    // 4. 必须包含至少一个数字或特殊符号
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    let has_special = s.contains('+') || s.contains('/') || s.contains('=');
    if !has_digit && !has_special {
        return false;
    }

    // 5. 校验大小写字母的分布比例，过高或过低都认为不是 Base64
    let prob = upper_prob(trimmed);
    if prob <= 0.2 || prob >= 0.8 {
        return false;
    }

    has_upper(s) && has_lower(s)
}

/// 统计字符串中各 ASCII 字符的出现频率，并按降序排序。
///
/// # 返回值
/// 返回一个向量，元素为 `(字符, 出现次数)`，按次数降序排列，次数相同时按字符升序排列。
#[inline]
pub fn sort_ascii_counts(input: &str, ignore_case: bool) -> Vec<(char, usize)> {
    let mut counts = [0usize; 256];

    for b in input.bytes() {
        if b.is_ascii() {
            let val = if ignore_case {
                b.to_ascii_lowercase() as usize
            } else {
                b as usize
            };
            counts[val] += 1;
        }
    }

    let mut result: Vec<(char, usize)> = counts
        .iter()
        .enumerate()
        .filter(|&(_, &count)| count > 0)
        .map(|(b, &count)| (b as u8 as char, count))
        .collect();

    // 优先按次数降序，次数相同则按字符 ASCII 码升序，保证稳定性
    result.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    result
}

/// 启发式判断字符串是否为一段连续或格式化的十六进制 (Hex) 数据。
///
/// 旨在精准提取代码或内存转储中的 Hex 序列，如 `\xAA\xBB`, `0x1a, 0x2b`, `AABBCC` 等。
///
/// # 过滤规则 (Heuristics)
/// 1. 过滤短文本，总长度需大于 10。
/// 2. 支持并提取常见前缀 (`0x`, `0X`, `\x`, `\X`, `%`)。
/// 3. **一致性检查**: 一个 Hex 串中的字母**不允许大小写混杂** (要么全是 `a-f`，要么全是 `A-F`)。
/// 4. **分隔符推导**: 如果字节之间有间隔，会自动推导分隔符（如空格、逗号等），并要求整个序列遵循该分隔符。
/// 5. 分隔符本身不能包含字母或数字，以防止错误截断。
pub fn is_hex(input: &str) -> bool {
    let mut s = input.trim();
    if s.is_empty() || !s.is_ascii() || s.len() <= 10 {
        return false;
    }

    // 处理全局仅带有一次前缀的情况 (例如 0xAABBCC)，剥离前缀当做纯 Hex 处理
    if (s.starts_with("0x") || s.starts_with("0X") || s.starts_with("\\x") || s.starts_with("\\X"))
        && s[2..].find(&s[0..2]).is_none()
    {
        s = &s[2..];
    }

    // 提取重复性前缀
    let prefix = if s.starts_with("0x") { "0x" }
    else if s.starts_with("0X") { "0X" }
    else if s.starts_with("\\x") { "\\x" }
    else if s.starts_with("\\X") { "\\X" }
    else if s.starts_with("%") { "%" }
    else { "" };

    let mut idx = prefix.len();
    let bytes = s.as_bytes();

    if idx + 2 > bytes.len() {
        return false;
    }

    let mut upper_hex = false;
    let mut lower_hex = false;

    // 内部校验是否为有效的 Hex 字符，并记录大小写状态
    #[inline]
    fn check_hex(b: u8, upper: &mut bool, lower: &mut bool) -> bool {
        if b.is_ascii_digit() { return true; }
        if (b'a'..=b'f').contains(&b) { *lower = true; return true; }
        if (b'A'..=b'F').contains(&b) { *upper = true; return true; }
        false
    }

    if !check_hex(bytes[idx], &mut upper_hex, &mut lower_hex) || !check_hex(bytes[idx+1], &mut upper_hex, &mut lower_hex) {
        return false;
    }
    idx += 2;

    // 推导字节之间的分隔符（如: 0xAA[分隔符]0xBB）
    let separator = if idx == bytes.len() {
        ""
    } else {
        if !prefix.is_empty() {
            if let Some(next_prefix_idx) = s[idx..].find(prefix) {
                &s[idx .. idx + next_prefix_idx]
            } else {
                return false;
            }
        } else {
            let mut sep_len = 0;
            while idx + sep_len < bytes.len() {
                let b = bytes[idx + sep_len];
                if b.is_ascii_hexdigit() {
                    break;
                }
                sep_len += 1;
            }
            &s[idx .. idx + sep_len]
        }
    };

    // 严禁分隔符包含字母和数字，避免解析错乱
    if !separator.is_empty() && separator.bytes().any(|b| b.is_ascii_alphanumeric()) {
        return false;
    }

    let mut curr_idx = 0;
    let mut count = 0;

    // 遍历循环验证整条数据链
    while curr_idx < bytes.len() {
        if !s[curr_idx..].starts_with(prefix) { return false; }
        curr_idx += prefix.len();

        if curr_idx + 2 > bytes.len() { return false; }

        if !check_hex(bytes[curr_idx], &mut upper_hex, &mut lower_hex) || !check_hex(bytes[curr_idx+1], &mut upper_hex, &mut lower_hex) {
            return false;
        }

        // 核心规则：十六进制字符串中的字母大小写必须保持一致
        if upper_hex && lower_hex {
            return false;
        }

        curr_idx += 2;
        count += 1;

        if curr_idx == bytes.len() {
            break;
        }

        if !s[curr_idx..].starts_with(separator) {
            return false;
        }
        curr_idx += separator.len();

        if curr_idx == bytes.len() {
            return false; // 结尾不能带着悬空的分隔符
        }
    }
    count > 0
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        has_keyword("","",true);
        has_keyword(&mut State::new(""),"",true);
    }
}