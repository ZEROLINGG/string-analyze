use crate::rules::lazy_rule;

// 1. Anthropic (Claude)
lazy_rule!(
    RE_ANTHROPIC_KEY = r#"\bsk-ant-(?:api03|oat01)-[A-Za-z0-9_-]{80,}\b"#,
    "发现 Anthropic (Claude) API Key",
    95
);

// 2. OpenRouter
lazy_rule!(
    RE_OPENROUTER_KEY = r#"\bsk-or-v1-[a-f0-9]{64}\b"#,
    "发现 OpenRouter API Key",
    90
);

// 3. Groq
lazy_rule!(
    RE_GROQ_KEY = r#"\bgsk_[A-Za-z0-9]{48,64}\b"#,
    "发现 Groq API Key",
    95
);

// 4. Hugging Face
lazy_rule!(
    RE_HUGGINGFACE_KEY = r#"\bhf_[A-Za-z0-9]{30,50}\b"#,
    "发现 Hugging Face Token",
    90
);

// 5. Perplexity
lazy_rule!(
    RE_PERPLEXITY_KEY = r#"\bpplx-[A-Za-z0-9]{40,60}\b"#,
    "发现 Perplexity API Key",
    90
);

// 6. NVIDIA NIM
lazy_rule!(
    RE_NVIDIA_NIM_KEY = r#"\bnvapi-[A-Za-z0-9_-]{60,80}\b"#,
    "发现 NVIDIA NIM API Key",
    90
);

// 7. xAI (Grok) - 同时支持官方 xai- 和旧版 xai-token-
lazy_rule!(
    RE_XAI_KEY = r#"\b(?:xai-token-|xai-)[A-Za-z0-9_-]{40,120}\b"#,
    "发现 xAI (Grok) API Key",
    90
);

// 8. Google Gemini / PaLM
lazy_rule!(
    RE_GEMINI_KEY = r#"\bAIzaSy[A-Za-z0-9_-]{33}\b"#,
    "发现 Google Gemini API Key",
    90
);

lazy_rule!(
    RE_OPENAI_KEY = r#"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_]{20,120}\b"#,
    "发现 OpenAI API Key",
    88,
    |slice, _input| {
        if slice.starts_with("sk-or-v1-") {
            return false;
        } // OpenRouter
        if slice.starts_with("sk-ant-") {
            return false;
        } // Anthropic

        if slice.len() == 35 && slice[3..].chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }

        if (40..=64).contains(&(slice.len() - 3))
            && slice[3..]
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return false;
        }

        true
    }
);

// 10. DeepSeek
lazy_rule!(
    RE_DEEPSEEK_KEY = r#"\bsk-[a-f0-9]{32}\b"#,
    "发现 DeepSeek API Key",
    85
);

// 11. SiliconFlow
lazy_rule!(
    RE_SILICONFLOW_KEY = r#"\bsk-[a-z0-9]{40,64}\b"#,
    "发现 SiliconFlow API Key",
    80
);

// 12. ElevenLabs
lazy_rule!(
    RE_ELEVENLABS_KEY = r#"\bsk_[a-f0-9]{48}\b"#,
    "发现 ElevenLabs API Key",
    75
);

// 13. Cerebras
lazy_rule!(
    RE_CEREBRAS_KEY = r#"\bcsk-[a-z0-9]{40,60}\b"#,
    "发现 Cerebras API Key",
    85
);

#[cfg(test)]
mod tests {
    use crate::analyze_with;
    use crate::rules::get_rules;

    #[test]
    fn test() {
        let input = r#"
flag{5tgb8uik,0ol}
deepseek_key = "sk-514d49dd9cd9111111b23a9b9fffffff";
siliconflow_key: sk-senitvfaimsnaxkhkhuskuekhbigijnpvtfcxqxiuaaaaaaa
xai_key = xai-token-saYrl4NtQZQ1nLBmFQUAHSwrDR0L4ZCg6kEafTrRsCkz4ZEjyfEkcGpwy2NXcSWQ9Z7KxaAAAAAAAAAA
xai_official = xai-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
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 # openrouter
openai_key = sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF
anthropic_key = sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
groq_key = gsk_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX
hf_token = hf_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ
pplx_key = pplx-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP
gemini_key = AIzaSyabcdefghijklmnopqrstuvwxyz1234567
nvapi_key = nvapi-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
"#;
        for line in input.lines() {
            println!(
                "{:#}",
                analyze_with(
                    line,
                    &get_rules(|m, _| module_path!().split("::tests").any(|s| s == m)),
                )
            )
        }
    }
}
