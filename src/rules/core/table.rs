use crate::rules::lazy_rule;

lazy_rule!(
    RE_TABLE_BASE64_STANDARD =
        r#"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/"#,
    "发现 标准 Base64 字符表",
    70
);
lazy_rule!(
    RE_TABLE_BASE64_URL = r#"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"#,
    "发现 URL-Safe Base64 字符表",
    70
);
lazy_rule!(
    RE_TABLE_BASE58_BTC = r#"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"#,
    "发现 Base58 字符表 (Bitcoin/IPFS 标准)",
    70
);
lazy_rule!(
    RE_TABLE_BASE58_RIPPLE = r#"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"#,
    "发现 Base58 字符表 (Ripple 瑞波币标准)",
    70
);
lazy_rule!(
    RE_TABLE_BASE32_RFC = r#"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"#,
    "发现 Base32 字符表 (RFC4648)",
    70
);
lazy_rule!(
    RE_TABLE_BASE32_HEX = r#"0123456789ABCDEFGHIJKLMNOPQRSTUV"#,
    "发现 Base32 字符表 (Hex 扩展)",
    70
);
lazy_rule!(
    RE_TABLE_BASE85_Z85 = r#"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/\*?&<>\(\)\[\]\{\}@%\$#"#,
    "发现 Z85 (ZeroMQ Base85) 字符表",
    70
);

lazy_rule!(
    RE_TABLE_ROT13 = r#"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"#,
    "发现 ROT13 对照字符表",
    70
);
lazy_rule!(
    RE_TABLE_QWERTY = r#"(?i)qwertyuiopasdfghjklzxcvbnm"#,
    "发现 QWERTY 键盘序字符表)",
    70
);
