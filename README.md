# string-analyze

[![Crates.io](https://img.shields.io/crates/v/string-analyze.svg)](https://crates.io/crates/string-analyze)
[![Documentation](https://docs.rs/string-analyze/badge.svg)](https://docs.rs/string-analyze)
[![License](https://img.shields.io/crates/l/string-analyze.svg)](https://github.com/ZEROLINGG/string-analyze/blob/main/LICENSE)

Find key strings from cluttered text — 基于规则流（Rule Flow）的高性能文本扫描引擎，支持并行匹配、多级过滤与高亮报告，常用于 CTF、敏感信息（API Key / Token）检测与高熵字符串提取。


## 特性

- **规则流引擎**：`AnyRule { flow, out }` 四阶段管道 — 基础提取 → 熵过滤 → 上下文断言 → 自定义校验（见 `src/rules.rs:378` `get_rules`）
- **并行扫描**：`analyze_with` 基于 `rayon` 并发执行全部规则（`src/lib.rs:195`）
- **复合熵评分**：融合香农熵、差分熵、2-gram 熵的加权幂平均（`P=-1.6`），归一化至 0–10，惩罚低随机性规律串（`src/entropy.rs:132` `composite_entropy`）
- **启发式校验**：`is_base64` / `is_hex` / `upper_prob` 等开箱即用（`src/tool.rs:244`, `src/tool.rs:376`）
- **合并高亮**：`AnalyzeResult` 自动合并重叠区间，`{:#}` 开启 ANSI 颜色（`src/lib.rs:240`）
- **分布式注册**：`lazy_rule!` + `inventory` 实现规则的声明式注册与 `ALL_RULES` 懒加载（`src/rules.rs:195`, `src/rules.rs:365`）
- **风险融合**：`AnalyzeResult::score()` 采用 `1 - ∏(1-Pi)` 独立事件联合公式，0–100 分（`src/lib.rs:227`）

## 快速开始

### 作为库

添加依赖到 `Cargo.toml`：

```toml
[dependencies]
string-analyze = "0.1.0"
```

基本用法：

```rust
use string_analyze::{analyze_with, rules::ALL_RULES};

fn main() {
    let input = r#"
Base64: mTyqm7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI== 444 m7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI==
api_key = "12345678abcdefgh";
"#;
    let result = analyze_with(input, ALL_RULES.as_slice());
    println!("score: {}", result.score());
    // `{:#}` 开启 ANSI 颜色高亮
    println!("{:#}", result);
}
```

按需过滤规则（按模块路径 / 重要程度）：

```rust
use string_analyze::rules::get_rules;

let rules = get_rules(|module_path, importance| {
    // 仅保留非 compiler 规则且 importance >= 30
    !module_path.contains("compiler") && importance >= 30
});
let result = string_analyze::analyze_with("AKIAIOSFODNN7EXAMPLE", &rules);
assert!(result.score() > 0);
```

自定义规则（`lazy_rule!` DSL）：

```rust,ignore
use string_analyze::lazy_rule;
use string_analyze::entropy::entropy;

lazy_rule!(
    RE_FLAG = r#"(?i)\b[a-z0-9_.-]{0,20}(?:flag|ctf)[a-z0-9\s-]{0,4}\{[^\{\}\n=\t()]{4,256}\}"#,
    "发现标准 flag",
    100
);
```

完整 DSL 参数顺序见 `src/rules.rs:144` 文档：`$name = $regex|closure, $describe, $importance [, $min_entropy] [, ($before,$after)] [, |slice,input| bool]`。

### 作为命令行工具

```bash
cargo install string-analyze
# 逐行扫描 stdin，仅输出命中（score != 0）的行
cat dump.txt | string-analyze
echo 'api_key = "12345678abcdefgh"' | string-analyze
echo "mTyqm7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI==" | string-analyze
```

`src/main.rs:5` 实现：按行读取 `stdin`，对每行执行 `analyze_with(&line, &ALL_RULES)` 并以 `{:#}` 打印高亮报告。

## 规则集

内置规则按目录组织（`src/rules/`）：

| 模块 | 说明 | 示例 |
|---|---|---|
| `rules::core::flag` | CTF flag 格式 | `flag{...}` |
| `rules::core::apikey` / `apikey_ai` / `cloudkey` | 云服务与 AI 提供商密钥 | AWS / Aliyun / OpenAI |
| `rules::core::hash` / `blockchain` / `pii` | 哈希、私钥、身份信息 | - |
| `rules::core::coding` / `compiler` / `constant` | 编码特征、编译产物、常量 | - |
| `rules::b64file` | Base64 编码的文件头 | `H4sI...` (gzip), `iVBORw0KGgo...` (PNG) |
| `rules::hexfile` | 十六进制转储 | `0xAA...` |
| `rules::coding` | 通用编码检测 | - |

所有规则通过 `ALL_RULES: LazyLock<Vec<AnyRule>>` (`src/rules.rs:365`) 懒加载，`get_rules` 支持过滤。

## API 概览

| 项 | 路径 | 说明 |
|---|---|---|
| `analyze_with` | `src/lib.rs:195` | 并行执行规则集，返回 `AnalyzeResult` |
| `AnyRule::new` / `add_flow` / `detect` | `src/lib.rs:148`, `src/lib.rs:161`, `src/lib.rs:173` | 规则构建与单条检测 |
| `State` / `RuleResult` / `Hit` / `AnalyzeResult` | `src/lib.rs:70`, `src/lib.rs:109`, `src/lib.rs:23`, `src/lib.rs:208` | 核心数据结构 |
| `entropy` / `delta_entropy` / `gram_entropy2` / `composite_entropy` | `src/entropy.rs:37`, `src/entropy.rs:57`, `src/entropy.rs:81`, `src/entropy.rs:132` | 熵计算 |
| `has_keyword` / `has_regex` / `is_base64` / `is_hex` | `src/tool.rs:61`, `src/tool.rs:187`, `src/tool.rs:244`, `src/tool.rs:376` | 匹配工具 |
| `lazy_rule!` / `RawRule` / `Assertion` | `src/rules.rs:195`, `src/rules.rs:65`, `src/rules.rs:21` | 规则定义 |

## 特性标志 (Feature Flags)

本项目当前未声明 `[features]`，`default` 即全量功能。

## 最小 Rust 版本 (MSRV)

**Rust 1.85**（见 `Cargo.toml` `rust-version`，`edition = "2024"` 要求的最低版本）。与 `rustc 1.98.1` 已验证通过。

## 开发

```bash
cargo check --all-targets --all-features
cargo test --doc --all-features
cargo test --all-features
cargo doc --no-deps --all-features
```

## 贡献

欢迎提交 Issue 与 Pull Request。请确保 `cargo test --doc` 与 `cargo doc` 无新增告警，新增公开 API 需补充 rustdoc 及 `CHANGELOG.md` 条目。

## 开源协议

本项目采用 [MIT](https://github.com/ZEROLINGG/string-analyze/blob/main/LICENSE) 协议，Copyright (c) 2026 ZEROLINGG。
