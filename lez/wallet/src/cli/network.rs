use std::{convert::Infallible, str::FromStr};

use url::Url;

const TESTNET_SEQUENCER_ADDR: &str = "https://testnet.lez.logos.co";
const LOCAL_SEQUENCER_ADDR: &str = "http://127.0.0.1:3040";

/// A `change-network` argument: `testnet`, `local`, or a custom sequencer URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkAlias {
    Testnet,
    Local,
    Other(String),
}

impl FromStr for NetworkAlias {
    type Err = Infallible;

    fn from_str(network: &str) -> Result<Self, Self::Err> {
        Ok(match network {
            "testnet" => Self::Testnet,
            "local" => Self::Local,
            other => Self::Other(other.to_owned()),
        })
    }
}

impl TryFrom<NetworkAlias> for Url {
    type Error = url::ParseError;

    fn try_from(alias: NetworkAlias) -> Result<Self, Self::Error> {
        match alias {
            NetworkAlias::Testnet => TESTNET_SEQUENCER_ADDR.parse(),
            NetworkAlias::Local => LOCAL_SEQUENCER_ADDR.parse(),
            NetworkAlias::Other(url) => url.parse(),
        }
    }
}
