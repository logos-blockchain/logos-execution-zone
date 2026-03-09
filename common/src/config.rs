//! Common configuration structures and utilities.

use std::str::FromStr;

use logos_blockchain_common_http_client::BasicAuthCredentials;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuth {
    pub username: String,
    pub password: Option<String>,
}

impl std::fmt::Display for BasicAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.username)?;
        if let Some(password) = &self.password {
            write!(f, ":{password}")?;
        }

        Ok(())
    }
}

impl FromStr for BasicAuth {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parse = || {
            let mut parts = s.splitn(2, ':');
            let username = parts.next()?;
            let password = parts.next().filter(|p| !p.is_empty());
            if parts.next().is_some() {
                return None;
            }

            Some((username, password))
        };

        let (username, password) = parse().ok_or_else(|| {
            anyhow::anyhow!("Invalid auth format. Expected 'user' or 'user:password'")
        })?;

        Ok(Self {
            username: username.to_owned(),
            password: password.map(std::string::ToString::to_string),
        })
    }
}

impl From<BasicAuth> for BasicAuthCredentials {
    fn from(value: BasicAuth) -> Self {
        Self::new(value.username, value.password)
    }
}
