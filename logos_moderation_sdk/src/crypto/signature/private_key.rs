use rand::{Rng as _, rngs::OsRng};

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKey([u8; 32]);

impl PrivateKey {
    #[must_use]
    pub fn new_os_random() -> Self {
        let mut rng = OsRng;
        loop {
            if let Ok(key) = Self::try_new(rng.r#gen()) {
                break key;
            }
        }
    }

    fn is_valid_key(value: [u8; 32]) -> bool {
        k256::SecretKey::from_bytes(&value.into()).is_ok()
    }

    pub fn try_new(value: [u8; 32]) -> Result<Self, &'static str> {
        if Self::is_valid_key(value) {
            Ok(Self(value))
        } else {
            Err("InvalidPrivateKey")
        }
    }

    #[must_use]
    pub const fn value(&self) -> &[u8; 32] {
        &self.0
    }
}