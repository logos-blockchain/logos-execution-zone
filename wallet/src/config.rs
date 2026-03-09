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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InitialAccountData {
    Public(InitialAccountDataPublic),
    Private(Box<InitialAccountDataPrivate>),
}

// Big difference in enum variants sizes
// however it is improbable, that we will have that much accounts, that it will substantialy affect
// memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PersistentAccountData {
    Public(PersistentAccountDataPublic),
    Private(Box<PersistentAccountDataPrivate>),
    Preconfigured(InitialAccountData),
}

/// A human-readable label for an account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Label(String);

impl Label {
    #[must_use]
    pub const fn new(label: String) -> Self {
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
    /// "2rnKprXqWGWJTkDZKsQbFXa4ctKRbapsdoTKQFnaVGG8").
    #[serde(default)]
    pub labels: HashMap<String, Label>,
}

impl PersistentStorage {
    pub fn from_path(path: &Path) -> Result<Self> {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "We want to provide a specific error message for not found case"
        )]
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
    #[must_use]
    pub fn account_id(&self) -> nssa::AccountId {
        match &self {
            Self::Public(acc) => acc.account_id,
            Self::Private(acc) => acc.account_id,
        }
    }
}

impl PersistentAccountData {
    #[must_use]
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
        Self::Private(Box::new(value))
    }
}

impl From<PersistentAccountDataPublic> for PersistentAccountData {
    fn from(value: PersistentAccountDataPublic) -> Self {
        Self::Public(value)
    }
}

impl From<PersistentAccountDataPrivate> for PersistentAccountData {
    fn from(value: PersistentAccountDataPrivate) -> Self {
        Self::Private(Box::new(value))
    }
}

impl From<InitialAccountData> for PersistentAccountData {
    fn from(value: InitialAccountData) -> Self {
        Self::Preconfigured(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasConfig {
    /// Gas spent per deploying one byte of data.
    pub gas_fee_per_byte_deploy: u64,
    /// Gas spent per reading one byte of data in VM.
    pub gas_fee_per_input_buffer_runtime: u64,
    /// Gas spent per one byte of contract data in runtime.
    pub gas_fee_per_byte_runtime: u64,
    /// Cost of one gas of runtime in public balance.
    pub gas_cost_runtime: u64,
    /// Cost of one gas of deployment in public balance.
    pub gas_cost_deploy: u64,
    /// Gas limit for deployment.
    pub gas_limit_deploy: u64,
    /// Gas limit for runtime.
    pub gas_limit_runtime: u64,
}

#[optfield::optfield(pub WalletConfigOverrides, rewrap, attrs = (derive(Debug, Default, Clone)))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Override rust log (env var logging level).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_rust_log: Option<String>,
    /// Sequencer URL.
    pub sequencer_addr: Url,
    /// Sequencer polling duration for new blocks.
    #[serde(with = "humantime_serde")]
    pub seq_poll_timeout: Duration,
    /// Sequencer polling max number of blocks to find transaction.
    pub seq_tx_poll_max_blocks: usize,
    /// Sequencer polling max number error retries.
    pub seq_poll_max_retries: u64,
    /// Max amount of blocks to poll in one request.
    pub seq_block_poll_max_amount: u64,
    /// Initial accounts for wallet.
    pub initial_accounts: Vec<InitialAccountData>,
    /// Basic authentication credentials.
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
                "account_id": "6iArKUXxhUJqS7kCaPNhwMWt3ro71PDyBj7jwAyE2VQV",
                "pub_sign_key": [
                    16,
                    162,
                    106,
                    154,
                    236,
                    125,
                    52,
                    184,
                    35,
                    100,
                    238,
                    174,
                    69,
                    197,
                    41,
                    77,
                    187,
                    10,
                    118,
                    75,
                    0,
                    11,
                    148,
                    238,
                    185,
                    181,
                    133,
                    17,
                    220,
                    72,
                    124,
                    77
                ]
            }
        },
        {
            "Public": {
                "account_id": "7wHg9sbJwc6h3NP1S9bekfAzB8CHifEcxKswCKUt3YQo",
                "pub_sign_key": [
                    113,
                    121,
                    64,
                    177,
                    204,
                    85,
                    229,
                    214,
                    178,
                    6,
                    109,
                    191,
                    29,
                    154,
                    63,
                    38,
                    242,
                    18,
                    244,
                    219,
                    8,
                    208,
                    35,
                    136,
                    23,
                    127,
                    207,
                    237,
                    216,
                    169,
                    190,
                    27
                ]
            }
        },
        {
            "Private": {
                "account_id": "FpdcxBrMkHWqXCBQ6FG98eYfWGY6jWZRsKNSi1FwDMxy",
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
                        239,
                        27,
                        159,
                        83,
                        199,
                        194,
                        132,
                        33,
                        20,
                        28,
                        217,
                        103,
                        101,
                        57,
                        27,
                        125,
                        84,
                        57,
                        19,
                        86,
                        98,
                        135,
                        161,
                        221,
                        108,
                        125,
                        152,
                        174,
                        161,
                        64,
                        16,
                        200
                    ],
                    "private_key_holder": {
                        "nullifier_secret_key": [
                            71,
                            195,
                            16,
                            119,
                            0,
                            98,
                            35,
                            106,
                            139,
                            82,
                            145,
                            50,
                            27,
                            140,
                            206,
                            19,
                            53,
                            122,
                            166,
                            76,
                            195,
                            0,
                            16,
                            19,
                            21,
                            143,
                            155,
                            119,
                            9,
                            200,
                            81,
                            105
                        ],
                        "viewing_secret_key": [
                            5,
                            117,
                            221,
                            27,
                            236,
                            199,
                            53,
                            22,
                            249,
                            231,
                            98,
                            147,
                            213,
                            116,
                            191,
                            82,
                            188,
                            148,
                            175,
                            98,
                            139,
                            52,
                            232,
                            249,
                            220,
                            217,
                            83,
                            58,
                            112,
                            155,
                            197,
                            196
                        ]
                    },
                    "nullifer_public_key": [
                        177,
                        64,
                        1,
                        11,
                        87,
                        38,
                        254,
                        159,
                        231,
                        165,
                        1,
                        94,
                        64,
                        137,
                        243,
                        76,
                        249,
                        101,
                        251,
                        129,
                        33,
                        101,
                        189,
                        30,
                        42,
                        11,
                        191,
                        34,
                        103,
                        186,
                        227,
                        230
                    ],
                    "viewing_public_key": [
                        2, 69, 126, 43, 158, 209, 172, 144, 23, 185, 208, 25, 163, 166, 176, 200, 225, 251, 106, 211, 4, 199, 112, 243, 207, 144, 135, 56, 157, 167, 32, 219, 38]
                }
            }
        },
        {
            "Private": {
                "account_id": "E8HwiTyQe4H9HK7icTvn95HQMnzx49mP9A2ddtMLpNaN",
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
                        48, 175, 124, 10, 230, 240, 166, 14, 249, 254, 157, 226, 208, 124, 122, 177, 203, 139, 192, 180, 43, 120, 55, 151, 50, 21, 113, 22, 254, 83, 148, 56],
                    "private_key_holder": {
                        "nullifier_secret_key": [
                            99, 82, 190, 140, 234, 10, 61, 163, 15, 211, 179, 54, 70, 166, 87, 5, 182, 68, 117, 244, 217, 23, 99, 9, 4, 177, 230, 125, 109, 91, 160, 30
                        ],
                        "viewing_secret_key": [
                            205, 32, 76, 251, 255, 236, 96, 119, 61, 111, 65, 100, 75, 218, 12, 22, 17, 170, 55, 226, 21, 154, 161, 34, 208, 74, 27, 1, 119, 13, 88, 128
                        ]
                    },
                    "nullifer_public_key": [
                        32, 67, 72, 164, 106, 53, 66, 239, 141, 15, 52, 230, 136, 177, 2, 236, 207, 243, 134, 135, 210, 143, 87, 232, 215, 128, 194, 120, 113, 224, 4, 165
                    ],
                    "viewing_public_key": [
                        2, 79, 110, 46, 203, 29, 206, 205, 18, 86, 27, 189, 104, 103, 113, 181, 110, 53, 78, 172, 11, 171, 190, 18, 126, 214, 81, 77, 192, 154, 58, 195, 238
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
    pub fn from_path_or_initialize_default(config_path: &Path) -> Result<Self> {
        match std::fs::File::open(config_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                Ok(serde_json::from_reader(reader)?)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                println!("Config not found, setting up default config");

                let config_home = config_path.parent().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Could not get parent directory of config file at {}",
                        config_path.display()
                    )
                })?;
                std::fs::create_dir_all(config_home)?;

                println!("Created configs dir at path {}", config_home.display());

                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(config_path)?;

                let config = Self::default();
                let default_config_serialized = serde_json::to_vec_pretty(&config).unwrap();

                file.write_all(&default_config_serialized)?;

                println!("Configs set up");
                Ok(config)
            }
            Err(err) => Err(err).context("IO error"),
        }
    }

    pub fn apply_overrides(&mut self, overrides: WalletConfigOverrides) {
        let Self {
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
