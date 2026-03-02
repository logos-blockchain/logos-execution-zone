use std::{
    collections::HashMap,
    io::{BufReader, Write as _},
    path::Path,
    time::Duration,
};

use anyhow::{Context as _, Result};
use common::config::BasicAuth;
use humantime_serde;
use key_protocol::key_management::{
    KeyChain,
    key_tree::{
        chain_index::ChainIndex, keys_private::ChildKeysPrivate, keys_public::ChildKeysPublic,
    },
};
use log::warn;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialAccountDataPublic {
    pub account_id: nssa::AccountId,
    pub pub_sign_key: nssa::PrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentAccountDataPublic {
    pub account_id: nssa::AccountId,
    pub chain_index: ChainIndex,
    pub data: ChildKeysPublic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialAccountDataPrivate {
    pub account_id: nssa::AccountId,
    pub account: nssa_core::account::Account,
    pub key_chain: KeyChain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentAccountDataPrivate {
    pub account_id: nssa::AccountId,
    pub chain_index: ChainIndex,
    pub data: ChildKeysPrivate,
}

// Big difference in enum variants sizes
// however it is improbable, that we will have that much accounts, that it will substantialy affect
// memory
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InitialAccountData {
    Public(InitialAccountDataPublic),
    Private(InitialAccountDataPrivate),
}

// Big difference in enum variants sizes
// however it is improbable, that we will have that much accounts, that it will substantialy affect
// memory
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PersistentAccountData {
    Public(PersistentAccountDataPublic),
    Private(PersistentAccountDataPrivate),
    Preconfigured(InitialAccountData),
}

/// A human-readable label for an account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Label(String);

impl Label {
    pub fn new(label: String) -> Self {
        Self(label)
    }
}

impl std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentStorage {
    pub accounts: Vec<PersistentAccountData>,
    pub last_synced_block: u64,
    /// Account labels keyed by account ID string (e.g.,
    /// "2rnKprXqWGWJTkDZKsQbFXa4ctKRbapsdoTKQFnaVGG8")
    #[serde(default)]
    pub labels: HashMap<String, Label>,
}

impl PersistentStorage {
    pub fn from_path(path: &Path) -> Result<Self> {
        match std::fs::File::open(path) {
            Ok(file) => {
                let storage_content = BufReader::new(file);
                Ok(serde_json::from_reader(storage_content)?)
            }
            Err(err) => match err.kind() {
                std::io::ErrorKind::NotFound => {
                    anyhow::bail!("Not found, please setup roots from config command beforehand");
                }
                _ => {
                    anyhow::bail!("IO error {err:#?}");
                }
            },
        }
    }
}

impl InitialAccountData {
    pub fn account_id(&self) -> nssa::AccountId {
        match &self {
            Self::Public(acc) => acc.account_id,
            Self::Private(acc) => acc.account_id,
        }
    }
}

impl PersistentAccountData {
    pub fn account_id(&self) -> nssa::AccountId {
        match &self {
            Self::Public(acc) => acc.account_id,
            Self::Private(acc) => acc.account_id,
            Self::Preconfigured(acc) => acc.account_id(),
        }
    }
}

impl From<InitialAccountDataPublic> for InitialAccountData {
    fn from(value: InitialAccountDataPublic) -> Self {
        Self::Public(value)
    }
}

impl From<InitialAccountDataPrivate> for InitialAccountData {
    fn from(value: InitialAccountDataPrivate) -> Self {
        Self::Private(value)
    }
}

impl From<PersistentAccountDataPublic> for PersistentAccountData {
    fn from(value: PersistentAccountDataPublic) -> Self {
        Self::Public(value)
    }
}

impl From<PersistentAccountDataPrivate> for PersistentAccountData {
    fn from(value: PersistentAccountDataPrivate) -> Self {
        Self::Private(value)
    }
}

impl From<InitialAccountData> for PersistentAccountData {
    fn from(value: InitialAccountData) -> Self {
        Self::Preconfigured(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasConfig {
    /// Gas spent per deploying one byte of data
    pub gas_fee_per_byte_deploy: u64,
    /// Gas spent per reading one byte of data in VM
    pub gas_fee_per_input_buffer_runtime: u64,
    /// Gas spent per one byte of contract data in runtime
    pub gas_fee_per_byte_runtime: u64,
    /// Cost of one gas of runtime in public balance
    pub gas_cost_runtime: u64,
    /// Cost of one gas of deployment in public balance
    pub gas_cost_deploy: u64,
    /// Gas limit for deployment
    pub gas_limit_deploy: u64,
    /// Gas limit for runtime
    pub gas_limit_runtime: u64,
}

#[optfield::optfield(pub WalletConfigOverrides, rewrap, attrs = (derive(Debug, Default, Clone)))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Override rust log (env var logging level)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_rust_log: Option<String>,
    /// Sequencer URL
    pub sequencer_addr: Url,
    /// Sequencer polling duration for new blocks
    #[serde(with = "humantime_serde")]
    pub seq_poll_timeout: Duration,
    /// Sequencer polling max number of blocks to find transaction
    pub seq_tx_poll_max_blocks: usize,
    /// Sequencer polling max number error retries
    pub seq_poll_max_retries: u64,
    /// Max amount of blocks to poll in one request
    pub seq_block_poll_max_amount: u64,
    /// Initial accounts for wallet
    pub initial_accounts: Vec<InitialAccountData>,
    /// Basic authentication credentials
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<BasicAuth>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            override_rust_log: None,
            sequencer_addr: "http://127.0.0.1:3040".parse().unwrap(),
            seq_poll_timeout: Duration::from_secs(12),
            seq_tx_poll_max_blocks: 5,
            seq_poll_max_retries: 5,
            seq_block_poll_max_amount: 100,
            basic_auth: None,
            initial_accounts: {
                let init_acc_json = r#"
 [
        {
            "Public": {
                "account_id": "CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r",
                "pub_sign_key": [
                    106,
                    164,
                    195,
                    101,
                    105,
                    155,
                    137,
                    217,
                    99,
                    239,
                    133,
                    165,
                    152,
                    104,
                    185,
                    97,
                    43,
                    96,
                    1,
                    249,
                    7,
                    80,
                    180,
                    151,
                    6,
                    98,
                    166,
                    39,
                    118,
                    51,
                    46,
                    129
                ]
            }
        },
        {
            "Public": {
                "account_id": "2RHZhw9h534Zr3eq2RGhQete2Hh667foECzXPmSkGni2",
                "pub_sign_key": [
                    137,
                    26,
                    226,
                    88,
                    249,
                    44,
                    168,
                    68,
                    122,
                    246,
                    207,
                    9,
                    196,
                    29,
                    150,
                    179,
                    160,
                    97,
                    135,
                    208,
                    152,
                    185,
                    26,
                    178,
                    204,
                    23,
                    180,
                    46,
                    60,
                    74,
                    47,
                    161
                ]
            }
        },
        {
            "Private": {
                "account_id": "HWkW5qd4XK3me6sCAb4bfPj462k33DjtKtEcYpuzNwB",
                "account": {
                    "program_owner": [
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0
                    ],
                    "balance": 10000,
                    "data": [],
                    "nonce": 0
                },
                "key_chain": {
                    "secret_spending_key": [
                        14,
                        202,
                        241,
                        109,
                        32,
                        181,
                        152,
                        140,
                        76,
                        153,
                        108,
                        57,
                        77,
                        192,
                        181,
                        97,
                        108,
                        144,
                        122,
                        45,
                        219,
                        5,
                        203,
                        193,
                        82,
                        123,
                        83,
                        34,
                        250,
                        214,
                        137,
                        63
                    ],
                    "private_key_holder": {
                        "nullifier_secret_key": [
                            174,
                            56,
                            101,
                            30,
                            248,
                            249,
                            100,
                            0,
                            122,
                            199,
                            209,
                            246,
                            58,
                            163,
                            223,
                            146,
                            59,
                            143,
                            78,
                            95,
                            41,
                            186,
                            106,
                            187,
                            53,
                            63,
                            75,
                            244,
                            233,
                            185,
                            110,
                            199
                        ],
                        "viewing_secret_key": [
                            251,
                            85,
                            223,
                            73,
                            142,
                            127,
                            134,
                            132,
                            185,
                            210,
                            100,
                            103,
                            198,
                            108,
                            229,
                            80,
                            176,
                            211,
                            249,
                            114,
                            110,
                            7,
                            225,
                            17,
                            7,
                            69,
                            204,
                            32,
                            47,
                            242,
                            103,
                            247
                        ]
                    },
                    "nullifer_public_key": [
                        139,
                        19,
                        158,
                        11,
                        155,
                        231,
                        85,
                        206,
                        132,
                        228,
                        220,
                        114,
                        145,
                        89,
                        113,
                        156,
                        238,
                        142,
                        242,
                        74,
                        182,
                        91,
                        43,
                        100,
                        6,
                        190,
                        31,
                        15,
                        31,
                        88,
                        96,
                        204
                    ],
                    "viewing_public_key": [
                        3,
                        136,
                        153,
                        50,
                        191,
                        184,
                        135,
                        36,
                        29,
                        107,
                        57,
                        9,
                        218,
                        135,
                        249,
                        213,
                        118,
                        215,
                        118,
                        173,
                        30,
                        137,
                        116,
                        77,
                        17,
                        86,
                        62,
                        154,
                        31,
                        173,
                        19,
                        167,
                        211
                    ]
                }
            }
        },
        {
            "Private": {
                "account_id": "HUpbRQ1vEcZv5y6TDYv9tpt1VA64ji2v4RDLJfK2rpZn",
                "account": {
                    "program_owner": [
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0
                    ],
                    "balance": 20000,
                    "data": [],
                    "nonce": 0
                },
                "key_chain": {
                    "secret_spending_key": [
                        32,
                        162,
                        244,
                        221,
                        2,
                        133,
                        168,
                        250,
                        240,
                        52,
                        92,
                        187,
                        157,
                        116,
                        249,
                        203,
                        143,
                        194,
                        214,
                        112,
                        115,
                        142,
                        153,
                        78,
                        241,
                        173,
                        103,
                        242,
                        192,
                        196,
                        29,
                        133
                    ],
                    "private_key_holder": {
                        "nullifier_secret_key": [
                            188,
                            235,
                            121,
                            54,
                            131,
                            206,
                            7,
                            215,
                            94,
                            231,
                            102,
                            22,
                            12,
                            27,
                            253,
                            161,
                            248,
                            206,
                            41,
                            160,
                            206,
                            149,
                            5,
                            217,
                            127,
                            235,
                            154,
                            230,
                            198,
                            232,
                            102,
                            31
                        ],
                        "viewing_secret_key": [
                            89,
                            116,
                            140,
                            122,
                            211,
                            179,
                            190,
                            229,
                            18,
                            94,
                            56,
                            235,
                            48,
                            99,
                            104,
                            228,
                            111,
                            72,
                            231,
                            18,
                            247,
                            97,
                            110,
                            60,
                            238,
                            138,
                            0,
                            25,
                            92,
                            44,
                            30,
                            145
                        ]
                    },
                    "nullifer_public_key": [
                        173,
                        134,
                        33,
                        223,
                        54,
                        226,
                        10,
                        71,
                        215,
                        254,
                        143,
                        172,
                        24,
                        244,
                        243,
                        208,
                        65,
                        112,
                        118,
                        70,
                        217,
                        240,
                        69,
                        100,
                        129,
                        3,
                        121,
                        25,
                        213,
                        132,
                        42,
                        45
                    ],
                    "viewing_public_key": [
                        2,
                        43,
                        42,
                        253,
                        112,
                        83,
                        195,
                        164,
                        26,
                        141,
                        92,
                        28,
                        224,
                        120,
                        155,
                        119,
                        225,
                        1,
                        45,
                        42,
                        245,
                        172,
                        134,
                        136,
                        52,
                        183,
                        170,
                        96,
                        115,
                        212,
                        114,
                        120,
                        37
                    ]
                }
            }
        }
    ]
                "#;
                serde_json::from_str(init_acc_json).unwrap()
            },
        }
    }
}

impl WalletConfig {
    pub fn from_path_or_initialize_default(config_path: &Path) -> Result<WalletConfig> {
        match std::fs::File::open(config_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                Ok(serde_json::from_reader(reader)?)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                println!("Config not found, setting up default config");

                let config_home = config_path.parent().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Could not get parent directory of config file at {config_path:#?}"
                    )
                })?;
                std::fs::create_dir_all(config_home)?;

                println!("Created configs dir at path {config_home:#?}");

                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(config_path)?;

                let config = WalletConfig::default();
                let default_config_serialized = serde_json::to_vec_pretty(&config).unwrap();

                file.write_all(&default_config_serialized)?;

                println!("Configs set up");
                Ok(config)
            }
            Err(err) => Err(err).context("IO error"),
        }
    }

    pub fn apply_overrides(&mut self, overrides: WalletConfigOverrides) {
        let WalletConfig {
            override_rust_log,
            sequencer_addr,
            seq_poll_timeout,
            seq_tx_poll_max_blocks,
            seq_poll_max_retries,
            seq_block_poll_max_amount,
            initial_accounts,
            basic_auth,
        } = self;

        let WalletConfigOverrides {
            override_rust_log: o_override_rust_log,
            sequencer_addr: o_sequencer_addr,
            seq_poll_timeout: o_seq_poll_timeout,
            seq_tx_poll_max_blocks: o_seq_tx_poll_max_blocks,
            seq_poll_max_retries: o_seq_poll_max_retries,
            seq_block_poll_max_amount: o_seq_block_poll_max_amount,
            initial_accounts: o_initial_accounts,
            basic_auth: o_basic_auth,
        } = overrides;

        if let Some(v) = o_override_rust_log {
            warn!("Overriding wallet config 'override_rust_log' to {v:#?}");
            *override_rust_log = v;
        }
        if let Some(v) = o_sequencer_addr {
            warn!("Overriding wallet config 'sequencer_addr' to {v}");
            *sequencer_addr = v;
        }
        if let Some(v) = o_seq_poll_timeout {
            warn!("Overriding wallet config 'seq_poll_timeout' to {v:?}");
            *seq_poll_timeout = v;
        }
        if let Some(v) = o_seq_tx_poll_max_blocks {
            warn!("Overriding wallet config 'seq_tx_poll_max_blocks' to {v}");
            *seq_tx_poll_max_blocks = v;
        }
        if let Some(v) = o_seq_poll_max_retries {
            warn!("Overriding wallet config 'seq_poll_max_retries' to {v}");
            *seq_poll_max_retries = v;
        }
        if let Some(v) = o_seq_block_poll_max_amount {
            warn!("Overriding wallet config 'seq_block_poll_max_amount' to {v}");
            *seq_block_poll_max_amount = v;
        }
        if let Some(v) = o_initial_accounts {
            warn!("Overriding wallet config 'initial_accounts' to {v:#?}");
            *initial_accounts = v;
        }
        if let Some(v) = o_basic_auth {
            warn!("Overriding wallet config 'basic_auth' to {v:#?}");
            *basic_auth = v;
        }
    }
}
