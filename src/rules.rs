//! 规则引擎核心定义与宏构建系统。
//!
//! 该模块定义了扫描规则的底层结构（如 `RawRule`、`Assertion`），
//! 并利用 `inventory` 库实现了规则的分布式注册。
//! 模块内提供的 `lazy_rule!` 宏是定义扫描规则的核心工具。

pub mod b64file;
pub mod coding;
pub mod core;
pub mod hexfile;

use std::collections::HashSet;
use std::sync::LazyLock;

use crate::entropy::composite_entropy;
use crate::{AnyRule, Hit, RuleResult, State};

/// 上下文断言 (Lookaround Assertion)。
///
/// 用于在命中主体内容后，检查其前置或后置文本是否符合特定条件。
pub struct Assertion {
    /// 检查的偏移量/最大窗口大小（字节数）。
    pub offset: usize,
    /// 期望的匹配结果：`true` 为正向断言（必须匹配），`false` 为负向断言（必须不匹配）。
    pub expected: bool,
    /// 用于断言的具体匹配逻辑（正则表达式或闭包）。
    pub find: Find,
}

/// 匹配查找器。
///
/// 封装了底层的匹配引擎，支持正则表达式或自定义的 Rust 闭包。
pub enum Find {
    /// 基于 `regex::Regex` 的正则匹配。
    Regex(regex::Regex),
    /// 自定义状态处理闭包，修改 `State` 并返回是否匹配成功。
    Fn(fn(&mut State) -> bool),
}

impl Find {
    /// 在给定的状态中执行查找，过滤并保留命中的范围。
    pub fn find(&self, state: &mut State) -> bool {
        match self {
            Find::Regex(regex) => has_regex(state, regex),
            Find::Fn(f) => f(state),
        }
    }

    /// 检查给定的字符串是否满足匹配条件（不保留命中范围，仅作布尔判断）。
    pub fn is_match(&self, input: &str) -> bool {
        match self {
            Find::Regex(regex) => regex.is_match(input),
            Find::Fn(_) => {
                let mut temp_state = State::new(input);
                self.find(&mut temp_state)
            }
        }
    }
}

/// 原始规则定义。
///
/// 包含了触发一次敏感信息扫描所需的所有静态配置（正则、描述、熵值要求、断言等）。
/// 最终会被转换并装载进 `AnyRule` 的执行流中。
pub struct RawRule {
    /// 基础匹配查找器（正则表达式或闭包）。
    pub find: Find,
    /// 规则的名称或描述。
    pub describe: &'static str,
    /// 规则重要程度（0-100），用于计算最终的风险评分。
    pub importance: u8,
    /// 最低复合熵值要求，低于此值的命中将被过滤（用于过滤死板的测试数据）。
    pub min_entropy: Option<f64>,
    /// 向前断言 (Lookbehind)：检查匹配文本之前的上下文。
    pub before_assert: Option<Assertion>,
    /// 向后断言 (Lookahead)：检查匹配文本之后的上下文。
    pub after_assert: Option<Assertion>,
    /// 组合逻辑控制：`true` 表示必须同时满足前后断言 (AND)，`false` 表示满足其一即可 (OR)。默认为 `true`。
    pub is_and_assert: bool,
    /// 最终的自定义校验闭包，参数为 `(&匹配片段, &完整文本)`，返回 `true` 表示校验通过。
    pub check: Option<fn(&str, &str) -> bool>,
}

impl RawRule {
    /// 执行自定义代码校验逻辑。
    pub fn check_custom(&self, state: &mut State) {
        if let Some(check_fn) = self.check {
            state.retain(|input, (start, end)| check_fn(&input[start..end], input));
        }
    }

    /// 执行上下文断言校验逻辑。
    fn check_assertions(&self, state: &mut State) {
        state.retain(|input, (start, end)| {
            // 1. 校验向前断言 (Lookbehind)
            let before_pass = self.before_assert.as_ref().map(|assert| {
                let mut check_start = start.saturating_sub(assert.offset);
                // 确保字符串切片落在安全的 UTF-8 字符边界上
                while check_start > 0 && !input.is_char_boundary(check_start) {
                    check_start -= 1;
                }
                let slice = &input[check_start..start];
                assert.find.is_match(slice) == assert.expected
            });

            // 2. 校验向后断言 (Lookahead)
            let after_pass = self.after_assert.as_ref().map(|assert| {
                let mut check_end = (end + assert.offset).min(input.len());
                // 确保字符串切片落在安全的 UTF-8 字符边界上
                while check_end < input.len() && !input.is_char_boundary(check_end) {
                    check_end += 1;
                }
                let slice = &input[end..check_end];
                assert.find.is_match(slice) == assert.expected
            });

            // 3. 结合两者的组合逻辑 (AND / OR)
            match (before_pass, after_pass) {
                (Some(b), Some(a)) => {
                    if self.is_and_assert {
                        b && a // 两个断言都必须满足
                    } else {
                        b || a // 满足任意一个断言即可
                    }
                }
                (Some(b), None) => b,
                (None, Some(a)) => a,
                (None, None) => true,
            }
        });
    }
}

/// 用于 `inventory` 收集的规则注册表项。
pub struct RuleEntry {
    pub name: &'static str,
    pub module_path: &'static str,
    pub importance: u8,
    pub get_rule: fn() -> &'static RawRule,
}

inventory::collect!(RuleEntry);

/// 核心规则定义宏。
///
/// 用于快速构建 `RawRule` 并自动注册到 `inventory` 中。
/// 支持多种参数组合，提供从基础匹配到复杂断言校验的极简 DSL 语法。
///
/// # 参数排列顺序（可选参数依次向后追加）
/// 1. `$name` (标识符) = `$regex` / `|$state| { ... }` : 规则名称与基础匹配逻辑
/// 2. `$describe` (字符串字面量): 规则描述
/// 3. `$importance` (数字): 严重程度 (0-100)
/// 4. `$min_entropy` (浮点数，可选): 最低熵值要求
/// 5. `$asserts` (元组，可选): 上下文断言定义 `(before_assert, after_assert, is_and_optional)`
/// 6. `$check` (闭包，可选): 自定义校验代码 `|slice, input| { bool }`
///
/// # 断言元组语法
/// - 断言格式: `(offset, expected, regex_or_closure)`
/// - 空断言: `None`
///
/// # 示例
/// ```rust,ignore
/// use string_analyze::lazy_rule;
/// use string_analyze::entropy::entropy;
/// lazy_rule!(
///     RE_FLAG = r#"(?i)\b[a-z0-9_.-]{0,20}(?:flag|ctf)[a-z0-9\s-]{0,4}\{[^\{\}\n=\t()]{4,256}\}"#,
///     "发现标准 flag",
///     100
/// );
/// lazy_rule!(
///     HIGH_ENTROPY = |s| if s.input.len() <= 512 && entropy(s.input.as_bytes()) >= 5.1 { s.ranges.push((0,s.input.len())); true } else { false } ,
///     "发现 高熵数据",
///     30
/// );
/// lazy_rule!(
///     RE_BRAINFUCK = r#"(?:[<>+\-.\[\],]{20,})"#,
///     "发现疑似 Brainfuck 代码",
///     40,
///     |slice, _input| {
///         let op_types = ['>', '<', '+', '-', '.', ',', '[', ']']
///             .iter()
///             .filter(|&&op| slice.contains(op))
///             .count();
///         op_types >= 2
///     }
/// );
/// lazy_rule!(
///     RE_PATH_UNIX = r#"(?:~|(?:\.\./|\./)|/)[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)+"#,
///     "发现 Unix 路径",
///     1,
///     ((8, false, r"(?i)(?:[a-z]:?|https?:/?/?)$"), ) // (前断言, 后断言)
/// );
/// ```
#[macro_export]
macro_rules! lazy_rule {

    // ==========================================
    // 基础公有匹配模式
    // ==========================================

    // 匹配闭包
    ($name:ident = |$state:ident| $find:expr, $describe:literal, $importance:literal $(, $($rest:tt)+)?) => {
        $crate::rules::lazy_rule!(@parse_args
            $name,
            $crate::rules::Find::Fn(|$state: &mut $crate::State| $find),
            $describe,
            $importance
            $(, $($rest)+)?
        );
    };
    // 匹配正则表达式
    ($name:ident = $re:literal, $describe:literal, $importance:literal $(, $($rest:tt)+)?) => {
        $crate::rules::lazy_rule!(@parse_args
            $name,
            $crate::rules::Find::Regex(regex::Regex::new($re).expect(concat!("Invalid regex in ", stringify!($name)))),
            $describe,
            $importance
            $(, $($rest)+)?
        );
    };

    // ==========================================
    // 中间宏：用来构建单一的 Assertion
    // ==========================================

    (@build_assert None) => { None };

    (@build_assert ($offset:expr, $expected:expr, $re:literal)) => {
        Some($crate::rules::Assertion {
            offset: $offset,
            expected: $expected,
            find: $crate::rules::Find::Regex(regex::Regex::new($re).expect("Invalid regex in assertion")),
        })
    };

    (@build_assert ($offset:expr, $expected:expr, |$state:ident| $func:expr)) => {
        Some($crate::rules::Assertion {
            offset: $offset,
            expected: $expected,
            find: $crate::rules::Find::Fn(|$state: &mut $crate::State| $func),
        })
    };

    // ==========================================
    // 中间宏：用来构建 (before, after, is_and) 断言元组
    // ==========================================

    // 1. 显式指定 is_and 参数: ($before, $after, false/true)
    (@build_assert_tuple ($before_assert:tt, $after_assert:tt, $is_and:expr)) => {
        (
            $crate::rules::lazy_rule!(@build_assert $before_assert),
            $crate::rules::lazy_rule!(@build_assert $after_assert),
            $is_and,
        )
    };
    // 2. 隐式关系（默认为与 / true）: ($before, $after)
    (@build_assert_tuple ($before_assert:tt, $after_assert:tt)) => {
        $crate::rules::lazy_rule!(@build_assert_tuple ($before_assert, $after_assert, true))
    };
    // 3. 仅向前断言: ($before, )
    (@build_assert_tuple ($before_assert:tt, )) => {
        (
            $crate::rules::lazy_rule!(@build_assert $before_assert),
            None,
            true,
        )
    };
    // 4. 仅向后断言: (, $after)
    (@build_assert_tuple (, $after_assert:tt)) => {
        (
            None,
            $crate::rules::lazy_rule!(@build_assert $after_assert),
            true,
        )
    };


    // ==========================================
    // 根基解析逻辑
    // ==========================================
    (@parse_args $name:ident, $filter:expr, $describe:literal, $importance:literal, $min_entropy:expr, $asserts:expr, $check:expr $(,)?) => {
        pub static $name: std::sync::LazyLock<$crate::rules::RawRule> = std::sync::LazyLock::new(|| {
            let asserts = $asserts;
            $crate::rules::RawRule {
                find: $filter,
                describe: $describe,
                importance: $importance,
                min_entropy: $min_entropy,
                before_assert: asserts.0,
                after_assert: asserts.1,
                is_and_assert: asserts.2,
                check: $check,
            }
        });
        inventory::submit! {
            $crate::rules::RuleEntry {
                name: stringify!($name),
                module_path: module_path!(),
                importance: $importance,
                get_rule: || &$name
            }
        }
    };

    // ==========================================
    // 参数组合重载解析
    // ==========================================

    // === 6 字段: 包含熵, 断言元组, 自定义 check ===
    (@parse_args $name:ident, $filter:expr, $describe:literal, $importance:literal, $min_entropy:expr, ($($asserts:tt)+), |$slice:pat_param,$input:pat_param| $check:expr $(,)?) => {
        $crate::rules::lazy_rule!(@parse_args $name, $filter, $describe, $importance, Some($min_entropy),
            $crate::rules::lazy_rule!(@build_assert_tuple ($($asserts)+)),
            Some(|$slice,$input| $check)
        );
    };

    // === 5 字段组合 ===
    // 无熵, 断言元组, 自定义 check
    (@parse_args $name:ident, $filter:expr, $describe:literal, $importance:literal, ($($asserts:tt)+), |$slice:pat_param,$input:pat_param| $check:expr $(,)?) => {
        $crate::rules::lazy_rule!(@parse_args $name, $filter, $describe, $importance, None,
            $crate::rules::lazy_rule!(@build_assert_tuple ($($asserts)+)),
            Some(|$slice,$input| $check)
        );
    };
    // 包含熵, 断言元组, 无 check
    (@parse_args $name:ident, $filter:expr, $describe:literal, $importance:literal, $min_entropy:expr, ($($asserts:tt)+) $(,)?) => {
        $crate::rules::lazy_rule!(@parse_args $name, $filter, $describe, $importance, Some($min_entropy),
            $crate::rules::lazy_rule!(@build_assert_tuple ($($asserts)+)),
            None
        );
    };
    // 包含熵, 无断言元组, 有 check
    (@parse_args $name:ident, $filter:expr, $describe:literal, $importance:literal, $min_entropy:expr, |$slice:pat_param,$input:pat_param| $check:expr $(,)?) => {
        $crate::rules::lazy_rule!(@parse_args $name, $filter, $describe, $importance, Some($min_entropy), (None, None, true), Some(|$slice,$input| $check));
    };

    // === 4 字段组合 ===
    // 无熵, 无断言元组, 有 check
    (@parse_args $name:ident, $filter:expr, $describe:literal, $importance:literal, |$slice:pat_param,$input:pat_param| $check:expr $(,)?) => {
        $crate::rules::lazy_rule!(@parse_args $name, $filter, $describe, $importance, None, (None, None, true), Some(|$slice,$input| $check));
    };
    // 无熵, 有断言元组, 无 check
    (@parse_args $name:ident, $filter:expr, $describe:literal, $importance:literal, ($($asserts:tt)+) $(,)?) => {
        $crate::rules::lazy_rule!(@parse_args $name, $filter, $describe, $importance, None,
            $crate::rules::lazy_rule!(@build_assert_tuple ($($asserts)+)),
            None
        );
    };
    // 有熵, 无断言元组, 无 check
    (@parse_args $name:ident, $filter:expr, $describe:literal, $importance:literal, $min_entropy:expr $(,)?) => {
        $crate::rules::lazy_rule!(@parse_args $name, $filter, $describe, $importance, Some($min_entropy), (None, None, true), None);
    };

    // === 3 字段 (最简版本) ===
    (@parse_args $name:ident, $filter:expr, $describe:literal, $importance:literal $(,)?) => {
        $crate::rules::lazy_rule!(@parse_args $name, $filter, $describe, $importance, None, (None, None, true), None);
    };
}

use crate::tool::has_regex;
pub use lazy_rule;

/// 全局预编译的所有规则实例。
/// 利用 `LazyLock` 在首次访问时加载并编译 `inventory` 收集到的规则。
pub static ALL_RULES: LazyLock<Vec<AnyRule>> = LazyLock::new(|| get_rules(|_, _| true));

/// 获取被编译和组装好的可执行规则集合 (`AnyRule`)。
///
/// # 参数
/// - `filter`: 闭包函数 `(模块路径, 重要程度) -> bool`。用于根据模块或严重程度过滤不需要的规则。
///
/// # 执行流 (Pipeline)
/// 构建的 `AnyRule` 将按照以下管道依次处理文本：
/// 1. **基础提取**：执行正则或基础闭包查找，圈定候选范围。
/// 2. **熵值过滤**（可选）：移除复合熵低于 `min_entropy` 的候选区间（过滤死板字符）。
/// 3. **上下文断言**（可选）：检查并过滤前后文不符合预期的区间。
/// 4. **自定义校验**（可选）：执行用户自定义的特定逻辑检查。
pub fn get_rules<F>(filter: F) -> Vec<AnyRule>
where
    F: Fn(&str, u8) -> bool,
{
    let mut rules = Vec::new();
    let mut seen_names = HashSet::new();

    for entry in inventory::iter::<RuleEntry> {
        // 1. 应用模块和严重程度过滤
        if filter(entry.module_path, entry.importance) {
            // 避免同名规则重复加载
            if !seen_names.insert(entry.name) {
                continue;
            }

            let r: &'static RawRule = (entry.get_rule)();

            // 2. 组装 AnyRule 执行流
            rules.push(
                AnyRule::new(|state| Hit {
                    describe: r.describe.into(),
                    importance: r.importance,
                    data: RuleResult::from(state),
                })
                // Flow 1: 基础查找
                .add_flow(move |state| r.find.find(state))
                // Flow 2: 复合熵值校验
                .add_flow(move |state| {
                    if let Some(min_ent) = r.min_entropy {
                        state.retain(|input, (start, end)| {
                            composite_entropy(&input.as_bytes()[start..end]) >= min_ent
                        });
                    }
                    !state.ranges.is_empty()
                })
                // Flow 3: 上下文断言校验 (Lookaround)
                .add_flow(move |state| {
                    r.check_assertions(state);
                    !state.ranges.is_empty()
                })
                // Flow 4: 自定义代码校验
                .add_flow(move |state| {
                    r.check_custom(state);
                    !state.ranges.is_empty()
                }),
            );
        }
    }

    rules
}
