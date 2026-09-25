use crate::rules::lazy_rule;

lazy_rule!(RE_MD5 = r#"(?i)\b[a-f0-9]{32}\b"#, "发现 MD5 哈希", 5, 5.0);
lazy_rule!(
    RE_SHA1 = r#"(?i)\b[a-f0-9]{40}\b"#,
    "发现 SHA-1 哈希",
    5,
    5.0
);
lazy_rule!(
    RE_SHA256 = r#"(?i)\b[a-f0-9]{64}\b"#,
    "发现 SHA-256 哈希",
    5,
    5.0
);
lazy_rule!(
    RE_SHA512 = r#"(?i)\b[a-f0-9]{128}\b"#,
    "发现 SHA-512 哈希",
    5,
    5.0
);