use crate::rules::lazy_rule;

lazy_rule!(
    RE_GITHUB_PAT = r#"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"#,
    "发现 Github Token",
    80
);
lazy_rule!(
    RE_GITHUB_FINEGRAINED = r#"\bgithub_pat_[A-Za-z0-9_]{60,}\b"#,
    "发现 Github Fine-grained Token",
    80
);
lazy_rule!(
    RE_SLACK_TOKEN = r#"\bxox[baprs]-[0-9]{10,13}-[a-zA-Z0-9-]{24,34}\b"#,
    "发现 Slack Token",
    80
);
lazy_rule!(
    RE_STRIPE_KEY = r#"\b[rs]k_(?:live|test)_[a-zA-Z0-9]{24}\b"#,
    "发现 Stripe API Key",
    80
);
lazy_rule!(
    RE_DISCORD_TOKEN = r#"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"#,
    "发现 Discord Token",
    80
);

lazy_rule!(
    RE_TELEGRAM_BOT = r#"\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b"#,
    "发现 Telegram Bot Token",
    80
);

lazy_rule!(
    RE_DIGITALOCEAN_TOKEN = r#"dop_v1_[a-f0-9]{64}"#,
    "发现 DigitalOcean Token",
    80
);
lazy_rule!(
    RE_NPM_TOKEN = r#"npm_[A-Za-z0-9]{36}"#,
    "发现 NPM Token",
    80
);
lazy_rule!(
    RE_PYPI_TOKEN = r#"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{70,}"#,
    "发现 PyPI Token",
    80
);
lazy_rule!(
    RE_SENDGRID_API = r#"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"#,
    "发现 SendGrid API Key",
    80
);
lazy_rule!(
    RE_TWILIO_KEY = r#"\bSK[0-9a-fA-F]{32}\b"#,
    "发现 Twilio API Key",
    80
);
lazy_rule!(
    RE_MAILGUN_API = r#"key-[a-f0-9]{32}"#,
    "发现 Mailgun API Key",
    80
);
lazy_rule!(
    RE_DOCKER_AUTH = r#""auth":\s*"[A-Za-z0-9+/=]{40,}""#,
    "发现 Docker Auth Token",
    80
);
lazy_rule!(
    RE_FIREBASE_URL = r#"https://[a-z0-9-]+\.firebaseio\.com"#,
    "发现 Firebase URL",
    80
);
lazy_rule!(
    RE_MONGODB_ATLAS = r#"mongodb\+srv://[^:@/]+:[^:@/]+@[a-z0-9.-]+\.mongodb\.net"#,
    "发现 MongoDB Atlas 凭证",
    80
);

lazy_rule!(
    RE_CLOUDFLARE_TOKEN = r#"(?i)\bcloudflare[_-]?api[_-]?token\s*[:=]\s*[A-Za-z0-9_-]{40}\b"#,
    "发现 Cloudflare API Token",
    80
);
lazy_rule!(
    RE_REPLICATE_TOKEN = r#"\br8_[A-Za-z0-9]{37}\b"#,
    "发现 Replicate API Token",
    80
);

#[cfg(test)]
mod tests {
    use crate::analyze_with;
    use crate::rules::get_rules;

    #[test]
    fn test() {
        let input = r#"
flag{5tgb8uik,0ol}

        "#;

        for line in input.lines() {
            println!(
                "{}",
                analyze_with(
                    line,
                    &get_rules(|m, _| module_path!().split("::tests").any(|s| s == m)),
                )
            )
        }
    }
}
