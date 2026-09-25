use crate::rules::lazy_rule;

// 算法常数
lazy_rule!(
    RE_MD5_MAGIC = r#"(?i)\b(?:67452301|efcdab89|98badcfe|10325476)\b"#,
    "发现 MD5 初始化幻数 (小端序/大端序常见特征)",
    70
);
lazy_rule!(
    RE_SHA1_MAGIC = r#"(?i)\b(?:67452301|efcdab89|98badcfe|10325476|c3d2e1f0)\b"#,
    "发现 SHA-1 初始化幻数",
    70
);
lazy_rule!(
    RE_SHA256_MAGIC = r#"(?i)\b(?:6a09e667|bb67ae85|3c6ef372|a54ff53a)\b"#,
    "发现 SHA-256 初始化幻数",
    70
);
lazy_rule!(
    RE_CRC32_POLY = r#"(?i)\b(?:edb88320|04c11db7)\b"#,
    "发现 CRC32 多项式常数",
    70
);
lazy_rule!(
    RE_CHACHA_SALSA = r#"expand (?:16|32)-byte k"#,
    "发现 ChaCha20 / Salsa20 初始化特征字符串",
    70
);
lazy_rule!(
    RE_BLOWFISH_PI = r#"(?i)\b(?:243f6a88|85a308d3|13198a2e|03707344)\b"#,
    "发现 Blowfish 圆周率 P-box 初始常数",
    70
);
lazy_rule!(
    RE_AES_POLY = r#"(?i)\b11b\b"#, // AES GF(2^8) 的不可约多项式 x^8+x^4+x^3+x+1，某些实现会硬编码
    "发现 疑似 AES 多项式常数 (0x11b)",
    70
);
lazy_rule!(
    RE_SECP256K1_P = r#"(?i)\bFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F\b"#,
    "发现 Secp256k1 (比特币) 椭圆曲线 Prime 参数",
    70
);
lazy_rule!(
    RE_ED25519_P = r#"(?i)\b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed\b"#,
    "发现 Ed25519 椭圆曲线 Prime 参数",
    70
);
lazy_rule!(
    RE_TEA_MAGIC = r#"(?i)\b(?:9e3779b9|2654435769)\b"#,
    "发现 TEA/XTEA/XXTEA 算法核心 Delta 常数",
    70
);
lazy_rule!(
    RE_RC4_SBOX_INIT = r#"(?i)\b(?:256|0x100)\s*(?:bytes|array|S-box|state)\b"#,
    "发现 疑似 RC4 初始化特征描述",
    70
);
lazy_rule!(
    RE_BLAKE2_IV = r#"(?i)\b(?:6a09e667f3bcc908|bb67ae8584caa73b)\b"#,
    "发现 BLAKE2 哈希算法初始化向量",
    70
);
