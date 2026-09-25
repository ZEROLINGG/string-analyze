use crate::rules::lazy_rule;

// 区块链
lazy_rule!(
    RE_BTC_ADDR = r#"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-za0-9]{11,71})\b"#,
    "发现 比特币(BTC) 地址",
    50,
    3.5
);
lazy_rule!(
    RE_ETH_ADDR = r#"\b0x[a-fA-F0-9]{40}\b"#,
    "发现 以太坊(ETH) 地址",
    48,
    3.2
); // hex max = 4.0
lazy_rule!(
    RE_SOLANA_ADDR = r#"\b[1-9A-HJ-NP-Za-km-z]{43,44}\b"#,
    "发现 Solana 地址",
    48,
    3.8
);
lazy_rule!(
    RE_MONERO_ADDR = r#"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"#,
    "发现 Monero (XMR) 地址",
    48,
    4.0
);

lazy_rule!(
    RE_PRIVATE_BLOCKCHAIN = r#"(?i)\b(?:trx|tether|litecoin)\s*[:=]?\s*0x[a-fA-F0-9]{40}\b"#,
    "发现 区块链转账线索",
    45,
    3.2
);
