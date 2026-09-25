# Changelog

所有重要变更将记录于此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added
- 预留：后续新增规则与 API 将在此记录。

## [0.1.0] - 2026-09-25

### Added
- 初始发布：基于 `AnyRule` 规则流引擎（`src/lib.rs:139`），支持 `flow` 四阶段管道与 `inventory` 分布式注册（`src/rules.rs:365` `ALL_RULES`）。
- 并行分析入口 `analyze_with` / `AnalyzeResult::score` 联合概率评分（`src/lib.rs:195`, `src/lib.rs:227`），`{:#}` ANSI 高亮输出。
- 熵模块：`entropy` / `delta_entropy` / `gram_entropy2` / `composite_entropy`（`src/entropy.rs:37` 起），`thread_local` 缓存优化 `gram_entropy2`。
- 工具模块：`has_keyword` / `has_chars` / `has_regex` / `is_base64` / `is_hex` / `sort_ascii_counts` 等启发式校验（`src/tool.rs`）。
- 宏 DSL：`lazy_rule!` 支持正则/闭包、熵阈值、上下文断言与自定义校验（`src/rules.rs:195`）。
- 内置规则集：`core`（flag/pii/apikey/cloudkey/hash/blockchain 等）、`b64file`、`hexfile`、`coding`（`src/rules/`）。
- 二进制工具：`src/main.rs` 逐行读取 `stdin` 并以高亮报告输出命中行。
- 文档：`README.md` 与 `rustdoc` 通过 `#![doc = include_str!("../README.md")]` 单一数据源同步；`Cargo.toml` 补齐 `repository` / `documentation` / `keywords` / `categories` / `rust-version` / `metadata.docs.rs` 发布元数据。

[Unreleased]: https://github.com/ZEROLINGG/string-analyze/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ZEROLINGG/string-analyze/releases/tag/v0.1.0
