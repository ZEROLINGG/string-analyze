use crate::rules::lazy_rule;

// Base64 文件
lazy_rule!(
    RE_B64_GZIP = r#"H4sI[A-Za-z0-9+/=]{20,}"#,
    "发现 Base64 编码的 Gzip 压缩流",
    42
);
lazy_rule!(
    RE_B64_ZLIB = r#"eNq[A-Za-z0-9+/=]{10,}"#,
    "发现 Base64 编码的 Zlib 数据",
    35
);
lazy_rule!(
    RE_B64_PNG = r#"iVBORw0KGgo[A-Za-z0-9+/=]{20,}"#,
    "发现 Base64 编码的 PNG 图片",
    40
);
lazy_rule!(
    RE_B64_JPEG = r#"/9j/[A-Za-z0-9+/=]{20,}"#,
    "发现 Base64 编码的 JPEG 图片",
    40
);
lazy_rule!(
    RE_B64_PDF = r#"JVBERi0xLj[A-Za-z0-9+/=]{10,}"#,
    "发现 Base64 编码的 PDF 文档",
    40
);
lazy_rule!(
    RE_B64_ZIP = r#"UEsDBB[A-Za-z0-9+/=]{10,}"#,
    "发现 Base64 编码的 ZIP 压缩包",
    40
);
lazy_rule!(
    RE_B64_GIF = r#"R0lGODlh[A-Za-z0-9+/=]{10,}"#,
    "发现 Base64 编码的 GIF 图片",
    45
);
lazy_rule!(
    RE_B64_PE = r#"TVqQAAMAAAA[A-Za-z0-9+/=]{10,}"#,
    "发现 Base64 编码的 Windows PE 程序",
    45
);
lazy_rule!(
    RE_B64_ELF = r#"f0VMRgIBAQ[A-Za-z0-9+/=]{10,}"#,
    "发现 Base64 编码的 Linux ELF 程序",
    45
);
lazy_rule!(
    RE_B64_SQLITE = r#"U1FMaXRlIGZvcm1hdCAz[A-Za-z0-9+/=]{0,}"#,
    "发现 Base64 编码的 SQLite 数据库",
    45
);
