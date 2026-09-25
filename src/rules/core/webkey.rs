use crate::rules::lazy_rule;

// web 凭证
lazy_rule!(
    RE_DB_CONN = r#"(?i)(?:mysql|postgresql|mongodb|redis|jdbc:[a-z]+)://[^\s]+"#,
    "发现 数据库连接字符串",
    80
);
lazy_rule!(
    RE_JWT = r#"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"#,
    "发现 JWT Token",
    80
);
lazy_rule!(
    RE_COOKIE = r#"(?i)(?:cookie|session)=[a-zA-Z0-9+/=]{20,}"#,
    "发现 Cookie/Session 凭证",
    80
);
lazy_rule!(
    RE_SPRING_SECRET =
        r#"(?i)\bspring\.(?:datasource\.(?:username|password)|redis\.password)\s*=\s*\S+"#,
    "发现 Spring 配置敏感信息",
    80
);
lazy_rule!(
    RE_DJANGO_SECRET = r#"(?i)SECRET_KEY\s*=\s*['"][A-Za-z0-9!@#$%^&*()_+=-]{32,}['"]"#,
    "发现 Django SECRET_KEY",
    80
);
lazy_rule!(
    RE_FLASK_SECRET = r#"(?i)app\.secret_key\s*=\s*['"][A-Za-z0-9!@#$%^&*()_+=-]{16,}['"]"#,
    "发现 Flask secret_key",
    80
);
lazy_rule!(
    RE_RAILS_SECRET = r#"(?i)secret_key_base\s*[:=]\s*['"][a-f0-9]{64,}['"]"#,
    "发现 Rails secret_key_base",
    80
);

