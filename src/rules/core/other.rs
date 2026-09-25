use crate::entropy::entropy;
use crate::rules::lazy_rule;

lazy_rule!(
    RE_SET_KEY = r#"(?i)(?:key|token)[a-z0-9_\-\s]{0,15}[=|:][\s]{0,5}(?:"|')?[a-z0-9_\-\.\+\/]{8,256}(?:"|')?"#,
    "发现 可疑key赋值",
    50
);

lazy_rule!(
    RE_TOR_ONION = r#"\b[a-z2-7]{16,56}\.onion\b"#,
    "发现 暗网 Onion 链接",
    50,
    3.0
);
lazy_rule!(
    RE_URL = r#"(?i)(?:https?|ftp)://(?:localhost|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?(?:/[^\s<>\"'{}|\\^`\\]*)?"#,
    "发现 URL 链接",
    5
);
lazy_rule!(
    RE_IPV4 = r#"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"#,
    "发现 IPv4 地址",
    10,
    ((1, false, r"\."), (1, false, r"\."))
);
lazy_rule!(
    RE_IPV6 = r#"\b(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:\b[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"#,
    "发现 IPv6 地址",
    10,
    2.0
);
lazy_rule!(
    RE_MAC = r#"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"#,
    "发现 mac 地址",
    10
);
lazy_rule!(
    RE_CIDR = r#"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b"#,
    "发现 CIDR",
    10
);

lazy_rule!(
    RE_UUID = r#"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#,
    "发现 UUID",
    8
);

lazy_rule!(
    RE_UNIX_TIMESTAMP = r#"\b1[0-9]{9,12}\b"#,
    "UNIX_TIMESTAMP",
    5
);
lazy_rule!(
    RE_ISO8601_DATETIME = r#"\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])[T\s](?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d{1,9})?)?(?:Z|[+-](?:0[0-9]|1[0-4]):?[0-5]\d)?\b"#,
    "发现 ISO8601 标准时间戳",
    5
);
lazy_rule!(
    RE_PATH_WIN = r#"(?i)^[a-z]:[/\\](?:[^\\/:*?"<>|\r\n\t]+[/\\])*[^\\/:*?"<>|\r\n\t]+"#,
    "发现 Windows 绝对路径",
    1
);
lazy_rule!(
    RE_PATH_UNIX = r#"(?:~|(?:\.\./|\./)|/)[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)+"#,
    "发现 Unix 路径",
    1,
    ((8, false, r"(?i)(?:[a-z]:?|https?:/?/?)$"),) // (前断言, 后断言)
);

lazy_rule!(
    HIGH_ENTROPY = |s| if s.input.len() <= 512 && entropy(s.input.as_bytes()) >= 5.9 {
        s.ranges.push((0, s.input.len()));
        true
    } else {
        false
    },
    "发现 高熵数据",
    30
);
