use crate::rules::lazy_rule;

// Hex 文件
lazy_rule!(
    RE_HEX_ZIP = r#"\b504b0304[0-9a-fA-F]{16,}\b"#,
    "发现 Hex 形式的 ZIP 文件头",
    45
);
lazy_rule!(
    RE_HEX_PNG = r#"\b89504e470d0a1a0a[0-9a-fA-F]{16,}\b"#,
    "发现 Hex 形式的 PNG 文件头",
    45
);
lazy_rule!(
    RE_HEX_JPEG = r#"\bffd8ffe[0-9a-fA-F]{16,}\b"#,
    "发现 Hex 形式的 JPEG 文件头",
    45
);
lazy_rule!(
    RE_HEX_PDF = r#"\b255044462d[0-9a-fA-F]{16,}\b"#,
    "发现 Hex 形式的 PDF 文件头",
    45
);
lazy_rule!(
    RE_HEX_ELF = r#"\b7f454c4601010100[0-9a-fA-F]{16,}\b"#,
    "发现 Hex 形式的 ELF 文件头",
    45
);
lazy_rule!(
    RE_CAFEBABE = r#"\bcafebabe[0-9a-fA-F]{16,}\b"#,
    "发现 Hex 形式的 Java Class 文件头",
    45
);
lazy_rule!(
    RE_HEX_RAR = r#"\b526172211a07[0-9a-fA-F]{16,}\b"#,
    "发现 Hex 形式的 RAR 文件头",
    45
);
lazy_rule!(
    RE_HEX_GZIP = r#"\b1f8b0800[0-9a-fA-F]{16,}\b"#,
    "发现 Hex 形式的 Gzip 文件头",
    45
);

#[cfg(test)]
mod tests {}
