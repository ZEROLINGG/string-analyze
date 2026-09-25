// string_analyze/src/rules/core/coding.rs
use crate::rules::lazy_rule;
use crate::tool::{is_base64, is_hex};

lazy_rule!(
    RE_BASE64 = r#"\b[A-Za-z0-9+/]{8,}={0,2}"#, // 筛选器
    "发现 Base64 编码数据",   // 描述
    40, // 重要性
    3.0,    // 最低混合熵要求
    |s, _| is_base64(s) // 验证闭包
);
lazy_rule!(
    RE_HEX = r#"(?i)(?:(?:0x|\\x|%)?[0-9a-f]{2}[\s,;:\-|]*){2,}(?:0x|\\x|%)?[0-9a-f]{2}"#,
    "发现 十六进制 (Hex) 编码数据",
    45,
    2.0,
    |s, _| is_hex(s)
);
lazy_rule!(
    RE_BRAINFUCK = r#"(?:[<>+\-.\[\],]{20,})"#,
    "发现疑似 Brainfuck 代码",
    40,
    |slice, _input| {
        let op_types = ['>', '<', '+', '-', '.', ',', '[', ']']
            .iter()
            .filter(|&&op| slice.contains(op))
            .count();
        op_types >= 2
    }
);
lazy_rule!(
    RE_JSFUCK = r#"(?:[\[\]()!+]\s*){20,}"#,
    "发现疑似 JSFuck 代码",
    40,
    |s, _| s.contains('!') || s.contains('(') || s.contains(')')
);
lazy_rule!(
    RE_MORSE = r#"(?:[.-]{1,6}(?:[ \t]+|[ \t]*/[ \t]*)){4,}[.-]{1,6}"#,
    "发现 摩斯电码",
    40
);
lazy_rule!(
    RE_BACON_HINT = r#"(?i)\b(?:aabbb|ababa|baaba|babba|abbba){5,}\b"#,
    "发现 疑似培根密码特征",
    40
);
lazy_rule!(
    RE_FOYAN = r#"佛?曰?[：:]?\s*[\u{4e00}-\u{9fa5}]{20,}"#,
    "发现 佛曰编码",
    40
);
lazy_rule!(
    RE_SHOUYIN = r#"[咯嘤呜呀哈嘿嗷啊~]{10,}"#,
    "发现 兽音编码",
    40
);

lazy_rule!(
    RE_OOK = r#"(?i)(?:Ook[.\!?]\s*){8,}"#,
    "发现 Ook! 混淆代码",
    45
);
lazy_rule!(
    RE_BRACKETS = r#"(?:[\[\](){}<>]\s*){20,}"#,
    "发现 括号混淆 特征",
    35
);
lazy_rule!(
    RE_ZERO_WIDTH = r#"[\u{200b}-\u{200f}\u{2060}\u{2061}\u{2062}\u{2063}\u{2064}\u{feff}]{10,}"#,
    "发现 零宽字符隐写",
    35
);

