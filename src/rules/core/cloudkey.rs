use crate::rules::lazy_rule;

// 云凭证
lazy_rule!(
    RE_AWS_AK = r#"(?i)\bAKIA[0-9A-Z]{16}\b"#,
    "发现 AWS Access Key",
    95
);
lazy_rule!(
    RE_RSA_KEY = r#"-----BEGIN (?:RSA )?PRIVATE KEY-----"#,
    "发现 RSA 私钥",
    95
);
lazy_rule!(
    RE_SSH_KEY = r#"ssh-(?:rsa|ed25519|dss) [A-Za-z0-9+/=]{100,}"#,
    "发现 SSH 密钥",
    95
);
lazy_rule!(
    RE_PGP = r#"-----BEGIN PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----"#,
    "发现 PGP 密钥",
    95
);
lazy_rule!(
    RE_AZURE_ACCESS_KEY =
        r#"(?i)DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]{88}"#,
    "发现 Azure 存储账户密钥",
    95
);
lazy_rule!(
    RE_GCP_SERVICE_ACCOUNT = r#"\{"type":\s*"service_account"[^}]{100,}\}"#,
    "发现 GCP 服务账户凭证",
    95
);
lazy_rule!(
    RE_GCP_OAUTH = r#"ya29\.[0-9A-Za-z\-_]+"#,
    "发现 GCP OAuth Token",
    95
);
lazy_rule!(
    RE_ALIYUN_AK = r#"(?i)LTAI[A-Za-z0-9]{12,20}"#,
    "发现 阿里云 Access Key",
    95
);
lazy_rule!(
    RE_TENCENT_AK = r#"\bAKID[A-Za-z0-9]{13,40}\b"#,
    "发现 腾讯云 Access Key",
    95
);
