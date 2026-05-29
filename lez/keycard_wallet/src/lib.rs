use std::path::PathBuf;

use lee::{AccountId, PublicKey, Signature};
use pyo3::{prelude::*, types::PyAny};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub mod python_path;

/// NSK and VSK as fixed-length zeroizing byte arrays.
type PrivateKeyPair = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

// TODO: encrypt at rest alongside broader wallet storage encryption work.
#[derive(Serialize, Deserialize)]
pub struct KeycardPairingData {
    pub index: u8,
    pub key: Vec<u8>,
}

impl KeycardPairingData {
    const fn is_valid(&self) -> bool {
        self.key.len() == 32 && self.index <= 4
    }
}

/// Rust wrapper around the Python `KeycardWallet` class.
pub struct KeycardWallet {
    instance: Py<PyAny>,
}

impl KeycardWallet {
    /// Create a new Python `KeycardWallet` instance.
    pub fn new(py: Python) -> PyResult<Self> {
        let module = py.import("keycard_wallet")?;
        let class = module.getattr("KeycardWallet")?;

        let instance = class.call0()?;

        Ok(Self {
            instance: instance.into(),
        })
    }

    pub fn is_unpaired_keycard_available(&self, py: Python) -> PyResult<bool> {
        self.instance
            .bind(py)
            .call_method0("is_unpaired_keycard_available")?
            .extract()
    }

    pub fn initialize(&self, py: Python<'_>, pin: &str) -> PyResult<bool> {
        self.instance
            .bind(py)
            .call_method1("initialize", (pin,))?
            .extract()
    }

    pub fn pair(&self, py: Python<'_>, pin: &str) -> PyResult<(u8, Vec<u8>)> {
        self.instance
            .bind(py)
            .call_method1("pair", (pin,))?
            .extract()
    }

    pub fn setup_communication_with_pairing(
        &self,
        py: Python<'_>,
        pin: &str,
        index: u8,
        key: &[u8],
    ) -> PyResult<bool> {
        self.instance
            .bind(py)
            .call_method1(
                "setup_communication_with_pairing",
                (pin, index, key.to_vec()),
            )?
            .extract()
    }

    pub fn close_session(&self, py: Python<'_>) -> PyResult<bool> {
        self.instance
            .bind(py)
            .call_method0("close_session")?
            .extract()
    }

    /// Connect using a stored pairing if available, falling back to a fresh pair.
    /// Saves any newly established pairing to disk.
    pub fn connect(&self, py: Python<'_>, pin: &str) -> PyResult<()> {
        if let Some(pairing) = load_pairing().filter(KeycardPairingData::is_valid)
            && self
                .setup_communication_with_pairing(py, pin, pairing.index, &pairing.key)
                .is_ok()
        {
            return Ok(());
        }
        let (index, key) = self.pair(py, pin)?;
        save_pairing(&KeycardPairingData { index, key });
        Ok(())
    }

    pub fn disconnect(&self, py: Python) -> PyResult<bool> {
        self.instance.bind(py).call_method0("disconnect")?.extract()
    }

    pub fn get_public_key_for_path(&self, py: Python, path: &str) -> PyResult<PublicKey> {
        let public_key: Vec<u8> = self
            .instance
            .bind(py)
            .call_method1("get_public_key_for_path", (path,))?
            .extract()?;

        let public_key: [u8; 32] = public_key.try_into().map_err(|vec: Vec<u8>| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "expected 32-byte public key from keycard, got {} bytes",
                vec.len()
            ))
        })?;

        PublicKey::try_new(public_key)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    pub fn get_public_key_for_path_with_connect(pin: &str, path: &str) -> PyResult<PublicKey> {
        Python::with_gil(|py| {
            python_path::add_python_path(py)?;
            let wallet = Self::new(py)?;
            wallet.connect(py, pin)?;
            let pub_key = wallet.get_public_key_for_path(py, path);
            drop(wallet.close_session(py));
            pub_key
        })
    }

    #[expect(
        clippy::arithmetic_side_effects,
        reason = "64 - s_stripped.len() is safe: s_stripped.len() ≤ 31 because py_signature.len() is in [32, 63]"
    )]
    pub fn sign_message_for_path(
        &self,
        py: Python,
        path: &str,
        message: &[u8; 32],
    ) -> PyResult<(Signature, PublicKey)> {
        let py_signature: Vec<u8> = self
            .instance
            .bind(py)
            .call_method1("sign_message_for_path", (message, path))?
            .extract()?;

        // The keycard Python library strips leading zeros from S when S < 2^(8k) for some k.
        // Left-pad S back to 32 bytes so the full signature is always 64 bytes (R || S).
        let py_signature = if py_signature.len() < 64 {
            if py_signature.len() < 32 {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "signature from keycard too short: {} bytes",
                    py_signature.len()
                )));
            }
            let s_stripped = &py_signature[32..];
            let mut padded = [0_u8; 64];
            padded[..32].copy_from_slice(&py_signature[..32]);
            padded[(64 - s_stripped.len())..].copy_from_slice(s_stripped);
            padded.to_vec()
        } else {
            py_signature
        };

        let signature: [u8; 64] = py_signature.try_into().map_err(|vec: Vec<u8>| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid signature length: expected 64 bytes, got {} (bytes: {:02x?})",
                vec.len(),
                vec
            ))
        })?;

        let sig = Signature { value: signature };
        let pub_key = self.get_public_key_for_path(py, path)?;
        if !sig.is_valid_for(message, &pub_key) {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "keycard returned a signature that does not verify against its own public key",
            ));
        }
        Ok((sig, pub_key))
    }

    pub fn sign_message_for_path_with_connect(
        pin: &str,
        path: &str,
        message: &[u8; 32],
    ) -> PyResult<(Signature, PublicKey)> {
        Python::with_gil(|py| {
            python_path::add_python_path(py)?;
            let wallet = Self::new(py)?;
            wallet.connect(py, pin)?;
            let result = wallet.sign_message_for_path(py, path, message);
            drop(wallet.close_session(py));
            result
        })
    }

    pub fn load_mnemonic(&self, py: Python, mnemonic: &str) -> PyResult<()> {
        self.instance
            .bind(py)
            .call_method1("load_mnemonic", (mnemonic,))?;
        Ok(())
    }

    pub fn get_public_account_id_for_path_with_connect(
        pin: &str,
        key_path: &str,
    ) -> PyResult<String> {
        let public_key = Self::get_public_key_for_path_with_connect(pin, key_path)?;

        Ok(format!("Public/{}", AccountId::from(&public_key)))
    }

    pub fn get_private_keys_for_path(&self, py: Python, path: &str) -> PyResult<PrivateKeyPair> {
        let (raw_nsk, raw_vsk): (Vec<u8>, Vec<u8>) = self
            .instance
            .bind(py)
            .call_method1("get_private_keys_for_path", (path,))?
            .extract()?;

        let raw_nsk = Zeroizing::new(raw_nsk);
        let raw_vsk = Zeroizing::new(raw_vsk);

        let nsk = {
            if raw_nsk.len() != 32 {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "expected 32-byte NSK from keycard, got {} bytes",
                    raw_nsk.len()
                )));
            }
            let mut arr = Zeroizing::new([0_u8; 32]);
            arr.copy_from_slice(&raw_nsk);
            arr
        };

        let vsk = {
            if raw_vsk.len() != 32 {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "expected 32-byte VSK from keycard, got {} bytes",
                    raw_vsk.len()
                )));
            }
            let mut arr = Zeroizing::new([0_u8; 32]);
            arr.copy_from_slice(&raw_vsk);
            arr
        };

        Ok((nsk, vsk))
    }

    pub fn get_private_keys_for_path_with_connect(
        pin: &str,
        path: &str,
    ) -> PyResult<PrivateKeyPair> {
        Python::with_gil(|py| {
            python_path::add_python_path(py)?;
            let wallet = Self::new(py)?;
            wallet.connect(py, pin)?;
            let result = wallet.get_private_keys_for_path(py, path);
            drop(wallet.disconnect(py));
            result
        })
    }
}

fn pairing_file_path() -> Option<PathBuf> {
    let home = std::env::var("LEE_WALLET_HOME_DIR")
        .map(PathBuf::from)
        .or_else(|_| {
            std::env::home_dir()
                .map(|h| h.join(".lee").join("wallet"))
                .ok_or(())
        })
        .ok()?;
    Some(home.join("keycard_pairing.json"))
}

fn load_pairing() -> Option<KeycardPairingData> {
    let path = pairing_file_path()?;
    let file = std::fs::File::open(path).ok()?;
    serde_json::from_reader(file).ok()
}

fn save_pairing(data: &KeycardPairingData) {
    if let Some(path) = pairing_file_path()
        && let Ok(json) = serde_json::to_vec_pretty(data)
    {
        drop(std::fs::write(path, json));
    }
}

pub fn clear_pairing() {
    if let Some(path) = pairing_file_path() {
        drop(std::fs::remove_file(path));
    }
}
