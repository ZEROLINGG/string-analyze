#![doc = include_str!("../README.md")]

pub mod entropy;
pub mod rules;
pub mod tool;

use rayon::prelude::*;
use std::borrow::Cow;
use std::fmt;
use std::fmt::Formatter;

/// 字符串索引范围别名，表示一段文本的 `(start, end)` 字节位置。
pub type UsizeRange = (usize, usize);

/// 规则命中的结果包装器。
///
/// 包含了命中的描述信息、重要程度（用于风险评分）以及附加数据。
#[derive(Debug)]
pub struct Hit<'a, D> {
    /// 规则的名称或描述信息，支持借用或拥有所有权的字符串。
    pub describe: Cow<'a, str>,
    /// 该规则的重要程度（0-100），用于后续计算综合风险评分。
    pub importance: u8,
    /// 命中的具体数据内容（通常是 `RuleResult`）。
    pub data: D,
}

impl<'a> fmt::Display for Hit<'a, RuleResult<'a>> {
    /// 格式化命中结果，用于控制台输出。
    ///
    /// 如果使用了替代格式化标志 `{:#}`，则会输出带有 ANSI 颜色的文本。
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let (reset, yellow, grey) = if f.alternate() {
            ("\x1b[0m", "\x1b[33m", "\x1b[90m")
        } else {
            ("", "", "")
        };

        // 打印 Hit 头信息，例如： ↳ [Base64]
        writeln!(
            f,
            "    {}↳{} [{}{}{}]",
            grey, reset, yellow, self.describe, reset
        )?;

        // 打印 Hit 捕获的具体内容
        for (i, extracted) in self.data.discovered.iter().enumerate() {
            // 对多行文本进行缩进处理，保持输出美观
            let cleaned_extracted = extracted.replace('\n', "\n          ");
            write!(f, "        {}↳{} {}", grey, reset, cleaned_extracted)?;
            // 如果不是最后一条数据，换行
            if i < self.data.discovered.len() - 1 {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

/// 规则执行过程中的中间状态。
///
/// 随着规则流（`flow`）的执行，`ranges` 可能会被修改、过滤或新增，
/// 最终通过的所有 `ranges` 将作为命中的结果。
#[derive(Debug)]
pub struct State<'a> {
    /// 待分析的原始输入文本。
    pub input: &'a str,
    /// 当前阶段捕获到的文本范围集合。
    pub ranges: Vec<UsizeRange>,
}

impl<'a> State<'a> {
    /// 创建一个新的空状态，准备开始规则匹配。
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            ranges: Vec::new(),
        }
    }

    /// 根据给定的闭包条件，保留符合要求的范围，移除不符合的范围。
    ///
    /// 此方法常用于在规则的后续步骤中对初步匹配结果进行二次过滤。
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&'a str, UsizeRange) -> bool,
    {
        let input = self.input;
        self.ranges.retain(|&r| f(input, r));
    }
}

impl<'a> From<&'a str> for State<'a> {
    fn from(s: &'a str) -> State<'a> {
        State::new(s)
    }
}

/// 规则执行完成后的最终提取结果。
///
/// 该结构体由 `State` 转换而来，除了保留索引范围外，
/// 还会实际切片提取出对应的字符串片段。
#[derive(Debug)]
pub struct RuleResult<'a> {
    /// 原始的完整输入文本。
    pub complete_input: &'a str,
    /// 最终命中的所有文本范围。
    pub ranges: Vec<UsizeRange>,
    /// 根据 `ranges` 从 `complete_input` 中切片提取出的实际文本内容。
    pub discovered: Vec<&'a str>,
}

impl<'a> From<State<'a>> for RuleResult<'a> {
    /// 将中间状态 `State` 转换为最终的 `RuleResult`。
    fn from(state: State<'a>) -> Self {
        let discovered = state
            .ranges
            .iter()
            .map(|&(s, e)| &state.input[s..e])
            .collect();
        Self {
            complete_input: state.input,
            ranges: state.ranges,
            discovered,
        }
    }
}

/// 灵活的规则定义器。
///
/// 一个规则由一系列的条件流（`flow`）和一个输出生成器（`out`）组成。
/// 只有当 `flow` 中的所有条件都返回 `true` 时，规则才算命中，
/// 并调用 `out` 生成最终的 `Hit` 报告。
pub struct AnyRule {
    /// 规则流：一系列依次执行的闭包，可修改 `State` 并返回是否继续执行。
    #[allow(clippy::type_complexity)]
    pub flow: Vec<Box<dyn for<'a> Fn(&mut State<'a>) -> bool + Send + Sync>>,
    /// 结果生成器：当所有 flow 都通过时，将 `State` 转换为 `Hit`。
    #[allow(clippy::type_complexity)]
    pub out: Box<dyn for<'a> Fn(State<'a>) -> Hit<'a, RuleResult<'a>> + Send + Sync>,
}

impl AnyRule {
    /// 创建一个新的规则，指定命中时的结果生成器。
    pub fn new<O>(out: O) -> Self
    where
        O: for<'a> Fn(State<'a>) -> Hit<'a, RuleResult<'a>> + Send + Sync + 'static,
    {
        Self {
            flow: Vec::new(),
            out: Box::new(out),
        }
    }

    /// 向规则流中追加一个处理步骤。
    ///
    /// 可以链式调用。
    pub fn add_flow<F>(mut self, flow: F) -> Self
    where
        F: for<'a> Fn(&mut State<'a>) -> bool + Send + Sync + 'static,
    {
        self.flow.push(Box::new(flow));
        self
    }

    /// 针对输入文本执行当前规则。
    ///
    /// 如果中途有任何一个 `flow` 返回 `false`，则返回 `None`。
    /// 否则返回包含提取数据的 `Hit`。
    pub fn detect<'a>(&self, input: &'a str) -> Option<Hit<'a, RuleResult<'a>>> {
        let mut state = State::new(input);

        for flow in &self.flow {
            if !flow(&mut state) {
                return None;
            }
        }
        Some((self.out)(state))
    }
}

/// 使用指定的规则集对文本进行并行分析。
///
/// 借助 `rayon`，所有的规则将并发执行以提升扫描效率。
///
/// # 参数
/// - `input`: 待分析的完整文本。
/// - `rules`: 需要应用的规则切片。
///
/// # 返回值
/// 返回包含所有命中结果的 `AnalyzeResult`。
pub fn analyze_with<'a>(input: &'a str, rules: &[AnyRule]) -> AnalyzeResult<'a> {
    AnalyzeResult {
        input,
        results: rules
            .par_iter()
            .filter_map(|rule| rule.detect(input))
            .collect(),
    }
}

/// 综合分析报告。
///
/// 包含了原始文本以及所有成功命中的规则结果。
pub struct AnalyzeResult<'a> {
    /// 原始被分析的文本。
    pub input: &'a str,
    /// 成功命中的规则及结果列表。
    pub results: Vec<Hit<'a, RuleResult<'a>>>,
}

impl<'a> AnalyzeResult<'a> {
    /// 创建一个新的分析报告实例。
    pub fn new(input: &'a str, results: Vec<Hit<'a, RuleResult<'a>>>) -> Self {
        Self { input, results }
    }

    /// 计算概率融合后的综合风险得分 (0 - 100)。
    ///
    /// # 算法说明
    /// 采用独立事件的概率联合公式：
    /// `P(联合) = 1 - ( (1 - P1) * (1 - P2) * ... )`
    /// 这意味着多条规则同时命中时，综合得分会向 100 逼近，但不会超过 100。
    pub fn score(&self) -> u8 {
        if self.results.is_empty() {
            return 0;
        }
        let mut fail_prob = 1.0f64;
        for hit in &self.results {
            let prob = (hit.importance as f64) / 100.0;
            fail_prob *= 1.0 - prob;
        }
        ((1.0 - fail_prob) * 100.0).round() as u8
    }
}

impl fmt::Display for AnalyzeResult<'_> {
    /// 格式化输出完整的分析报告。
    ///
    /// 该实现会完成两项工作：
    /// 1. 打印原始文本，并将所有命中规则的文本片段进行高亮（支持重叠区间的合并合并）。
    /// 2. 依次列出所有命中规则的详细信息（名称、提取内容等）。
    ///
    /// 支持使用 `{:#}` 开启 ANSI 颜色输出。
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.results.is_empty() {
            return write!(f, "{}", self.input);
        }

        // 借助 f.alternate() (即使用 {:#}) 来判断是否应用 ANSI 颜色
        let ansi = f.alternate();
        let (reset, red) = if ansi {
            ("\x1b[0m", "\x1b[31m")
        } else {
            ("", "")
        };

        // 提取所有的命中区间并进行合并处理，防止高亮输出时发生错乱
        let mut all_ranges: Vec<UsizeRange> = self
            .results
            .iter()
            .flat_map(|hit| hit.data.ranges.iter().copied())
            .collect();

        // 按起点排序
        all_ranges.sort_unstable_by_key(|r| r.0);

        let mut merged_ranges: Vec<UsizeRange> = Vec::with_capacity(all_ranges.len());
        for r in all_ranges {
            if let Some(last) = merged_ranges.last_mut() {
                // 如果当前区间与上一个区间有重叠，则合并区间
                if r.0 <= last.1 {
                    last.1 = last.1.max(r.1);
                    continue;
                }
            }
            merged_ranges.push(r);
        }

        // 边遍历边向 formatter 写入文本和高亮代码，免去巨大的 String 内存分配开销
        let mut cursor = 0;
        for &(start, end) in &merged_ranges {
            // 安全检查：确保切片边界落在合法的 UTF-8 字符边界上
            if !self.input.is_char_boundary(start) || !self.input.is_char_boundary(end) {
                continue;
            }

            if start > cursor {
                write!(f, "{}", &self.input[cursor..start])?;
            }
            // 写入高亮部分
            write!(f, "{}{}{}", red, &self.input[start..end], reset)?;

            cursor = end;
        }
        // 补全末尾未高亮的文本
        if cursor < self.input.len() {
            write!(f, "{}", &self.input[cursor..])?;
        }

        writeln!(f)?; // 在原文本和分析报告之间加一个换行

        // 借助 Hit 的 fmt::Display 实现生成 Hits 列表报告
        for (i, hit) in self.results.iter().enumerate() {
            if ansi {
                write!(f, "{:#}", hit)?;
            } else {
                write!(f, "{}", hit)?;
            }

            if i < self.results.len() - 1 {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::ALL_RULES;

    #[test]
    fn test_comprehensive() {
        let input = r#"
Base64: mTyqm7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI== 444 m7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI==
api_key =
"12345678abcdefgh";
        "#;

        let result = analyze_with(input, ALL_RULES.as_slice());
        let score = result.score();

        // 使用 {:#} 触发带颜色的控制台输出
        println!("[综合测试评分: {score}]\n{:#}", result);
    }
}
