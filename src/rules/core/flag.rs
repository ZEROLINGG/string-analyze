use std::sync::LazyLock;

use crate::rules::lazy_rule;
use crate::tool::{has_chars, has_keyword};
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD};
use base64::Engine;
use hex;

const FLAG_PREFIXES: &[&str] = &[
    "flag",
    "ctf",
    "bugku",
    "htb",
    "thm",
    "picoctf",
    "nssctf",
    "dasctf",
    "ciscn",
    "cyberpeace",
    "qwb",
    "xctf",
    "iscc",
    "seccon",
    "pctf",
    "actf",
    "mrctf",
    "vnctf",
    "litctf",
    "adworld",
    "roarctf",
    "flare",
];


static FLAG_PREFIXES_B64: LazyLock<Vec<String>> = LazyLock::new(|| {
    FLAG_PREFIXES
        .iter()
        .map(|s| {
            let encoded = BASE64_STANDARD.encode(format!("{s}{{"));
            let trimmed = encoded.trim_end_matches('=');
            let invariant_len = ((s.len() + 1) * 8) / 6;
            trimmed[..invariant_len.min(trimmed.len())].to_string()
        })
        .collect::<Vec<_>>()
});

static FLAG_PREFIXES_HEX: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut hex_patterns = Vec::new();

    for s in FLAG_PREFIXES {
        let bytes = format!("{s}{{").into_bytes();

        hex_patterns.push(hex::encode(&bytes));

        let escaped: String = bytes.iter().map(|b| format!("\\x{:02x}", b)).collect();
        hex_patterns.push(escaped);

        let ox_formatted: String = bytes.iter()
            .map(|b| format!("0x{:02x}", b))
            .collect::<Vec<_>>()
            .join(","); // "0x66,0x6c,0x61..."
        hex_patterns.push(ox_formatted);

        let space_separated: String = bytes.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        hex_patterns.push(space_separated);
    }

    hex_patterns
});

lazy_rule!(
    RE_FLAG = r#"(?i)\b[a-z0-9_.-]{0,20}(?:flag|ctf)[a-z0-9\s-]{0,4}\{[^\{\}\n=\t()]{4,256}\}"#,
    "发现标准 flag",
    100
);

lazy_rule!(
    RE_PLATFORM_FLAG = r#"(?i)\b(?:bugku|htb|thm|picoctf|nssctf|dasctf|ciscn|cyberpeace|qwb|xctf|iscc|seccon|pctf|actf|mrctf|vnctf|litctf|adworld|roarctf|flare)[a-z0-9_-]{0,4}\{[^\{\}\n=\t()]{4,256}\}"#,
    "发现 特定平台/赛事的 flag",
    100
);

lazy_rule!(
    FLAG1 = |state| (state.input.len() < 256)
        && FLAG_PREFIXES
            .iter()
            .any(|&prefix| has_keyword(&mut *state, prefix, true)),
    "存在已知flag前缀以及 '{','}'",
    70,
    |_,input| has_chars(
            input,
            &['{', '}'],
            false,
            false
        ) && !has_chars(
            input,
            &['(', ')', '[',']','=', ' ','`','"','\'',';',':'],
            true,
            false
        )
);

lazy_rule!(
    FLAG2 = |state| (state.input.len() < 256)
        && FLAG_PREFIXES.iter().any(|&prefix| {
            let chars_vec: Vec<char> = prefix.chars().collect();
            has_chars(&mut *state, &chars_vec, false, true)
        }),
    "存在被打乱的flag前缀字符并且含有 '{','}'",
    45,
    |_,input| has_chars(
            input,
            &['{', '}'],
            false,
            false
        ) && !has_chars(
            input,
            &['(', ')', '[',']','=', ' ','`','"','\'',';',':'],
            true,
            false
        )
);

lazy_rule!(
    FLAG_B64 = |state| (state.input.len() >= 16)
        && FLAG_PREFIXES_B64
            .iter()
            .any(|b64_prefix| has_keyword(&mut *state, b64_prefix, false)),
    "疑似 Base64 编码的 flag前缀",
    65

);

lazy_rule!(
    FLAG_HEX = |state| (state.input.len() >= 16)
        && FLAG_PREFIXES_HEX
            .iter()
            .any(|hex_prefix| has_keyword(&mut *state, hex_prefix, true)),
    "疑似 Hex 编码的 flag前缀",
    65
);


#[cfg(test)]
mod tests {
    use crate::analyze_with;
    use crate::rules::get_rules;

    #[test]
    fn test() {
        let input = r#"
flag{5tgb8uik,0ol}
buuctf{aaac38f5-046b-43e8-a089-03813226d280}
fgaag_!l{_oun}amb_ob # railfence_group 3
hex_flag = 666c61677b68656c6c6f5f63746665727d
b64_flag = ZmxhZ3s1dGdiOHVpaywwb2x9
b64_ctf = Y3Rme3Rlc3RfMTIzNH0=
66 6c 61 67 7b 68 65 6c 6c 6f 5f 63 74 66 65 72 7d
66%6c%61%67%7b%68%65%6c%6c%6f%5f%63%74%66%65%72%7d
0x66,0x6c,0x61,0x67,0x7b,0x68,0x65,0x6c,0x6c,0x6f,0x5f,0x63,0x74,0x66,0x65,0x72,0x7d
0x660x6c0x610x670x7b0x680x650x6c0x6c0x6f0x5f0x630x740x660x650x720x7d
\x66\x6c\x61\x67\x7b\x68\x65\x6c\x6c\x6f\x5f\x63\x74\x66\x65\x72\x7d
66,6c,61,67,7b,68,65,6c,6c,6f,5f,63,74,66,65,72,7d
"#;
        for line in input.lines() {
            if line.trim().is_empty() {
                continue;
            }
            println!("{}", analyze_with(
                line,
                &get_rules(|m, _| module_path!().split("::tests").any(|s| s == m)),
            ))
        }
    }
}