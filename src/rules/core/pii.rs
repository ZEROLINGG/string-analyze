//string_analyze/src/rules/core/pii.rs
use crate::rules::lazy_rule;

fn luhn_check(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let checksum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(idx, &d)| {
            if idx % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();

    checksum % 10 == 0
}
fn is_valid_bin(card: &str) -> bool {
    if card.len() < 6 {
        return false;
    }
    const VALID_BINS: &[&str] = &[
        "62",   // 银联
        "4",    // Visa
        "5",    // Mastercard
        "35",   // JCB
        "37",   // Amex
        "6011", // Discover
        "622",  // 中国银联
    ];

    VALID_BINS.iter().any(|&bin| card.starts_with(bin))
}

fn id_card_check(id: &str) -> bool {
    if id.len() != 18 {
        return false;
    }

    let weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    let check_codes = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];

    let sum: u32 = id[..17]
        .chars()
        .filter_map(|c| c.to_digit(10))
        .enumerate()
        .map(|(i, d)| d * weights[i])
        .sum();

    let expected = check_codes[(sum % 11) as usize];
    let actual = id.chars().nth(17).unwrap_or(' ').to_ascii_uppercase();

    expected == actual
}

lazy_rule!(
    RE_CREDIT_CARD = r"\b[1-9]\d{12,18}\b",
    "发现 疑似信用卡号",
    90,
    |input,_| is_valid_bin(input) && luhn_check(input)
);

lazy_rule!(
    RE_CN_ID_CARD =
        r#"[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]"#,
    "发现 疑似中国大陆身份证号",
    90,
    |input,_| id_card_check(input)
);

lazy_rule!(
    RE_CN_PHONE = r#"\b1[3-9]\d{9}\b"#,
    "发现 疑似手机号",
    60,
    ((10, false, r"(?i)(order|id|stamp|time)"), )
);
lazy_rule!(
    RE_PASSPORT = r#"\b[A-Z]{1,2}[0-9]{6,9}\b"#,
    "发现 疑似护照号",
    90
);
lazy_rule!(
    RE_HKID = r#"\b[A-Z]{1,2}\d{6}\([0-9A]\)"#,
    "发现 香港身份证号",
    90
);
lazy_rule!(
    RE_EMAIL = r#"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"#,
    "发现 邮箱地址",
    60
);

fn usci_check(s: &str) -> bool {
    if s.len() != 18 {
        return false;
    }
    let dict = "0123456789ABCDEFGHJKLMNPQRTUWXY";
    let weights = [
        1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 14, 12, 5, 15, 14, 12,
    ];

    let mut sum = 0;
    for (i, c) in s[..17].chars().enumerate() {
        if let Some(val) = dict.find(c) {
            sum += val * weights[i];
        } else {
            return false;
        }
    }

    let check_val = 31 - (sum % 31);
    let check_char = if check_val == 31 {
        '0'
    } else {
        dict.chars().nth(check_val).unwrap()
    };

    s.ends_with(check_char)
}

lazy_rule!(
    RE_CN_USCI = r#"[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}"#,
    "发现 统一社会信用代码",
    90,
    |input,_| usci_check(input)
);

lazy_rule!(
    RE_TW_ID = r"\b[A-Z][12]\d{8}\b",
    "发现 台湾身份证号",
    90,
    |input,_| tw_id_check(input)
);

fn tw_id_check(id: &str) -> bool {
    if id.len() != 10 {
        return false;
    }

    // 第一个字母对应数字
    let first_num = match id.chars().next() {
        Some('A') => 10,
        Some('B') => 11,
        Some('C') => 12,
        Some('D') => 13,
        Some('E') => 14,
        Some('F') => 15,
        Some('G') => 16,
        Some('H') => 17,
        Some('I') => 34,
        Some('J') => 18,
        Some('K') => 19,
        Some('L') => 20,
        Some('M') => 21,
        Some('N') => 22,
        Some('O') => 35,
        Some('P') => 23,
        Some('Q') => 24,
        Some('R') => 25,
        Some('S') => 26,
        Some('T') => 27,
        Some('U') => 28,
        Some('V') => 29,
        Some('W') => 32,
        Some('X') => 30,
        Some('Y') => 31,
        Some('Z') => 33,
        _ => return false,
    };

    let weights = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1];
    let sum: u32 = (first_num / 10) * weights[0]
        + (first_num % 10) * weights[1]
        + id[1..]
            .chars()
            .filter_map(|c| c.to_digit(10))
            .zip(&weights[2..])
            .map(|(d, &w)| d * w)
            .sum::<u32>();

    sum % 10 == 0
}

lazy_rule!(RE_MO_ID = r"\b[1578]\d{6}\(\d\)\b", "发现 澳门身份证号", 90);
