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
            password: password.map(str::to_owned),
        })
    }
}

impl From<BasicAuth> for BasicAuthCredentials {
    fn from(value: BasicAuth) -> Self {
        Self::new(value.username, value.password)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::BasicAuth;

    #[test]
    fn parse_preserves_non_empty_password() {
        let auth = BasicAuth::from_str("user:secret").expect("must parse");
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password.as_deref(), Some("secret"));
    }

    #[test]
    fn parse_empty_password_is_none() {
        // A trailing colon means an empty password, which must become `None`.
        // Catches deletion of `!` in `.filter(|p| !p.is_empty())`, which would
        // instead yield `Some("")`.
        let auth = BasicAuth::from_str("user:").expect("must parse");
        assert_eq!(auth.password, None);
    }

    #[test]
    fn parse_username_only_has_no_password() {
        let auth = BasicAuth::from_str("alice").expect("must parse");
        assert_eq!(auth.username, "alice");
        assert_eq!(auth.password, None);
    }
}
