use std::path::PathBuf;

use nssa::{AccountId, PublicKey, Signature};
use pyo3::{prelude::*, types::PyAny};
use serde::{Deserialize, Serialize};

pub mod python_path;

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

    pub fn get_pairing_data(&self, py: Python<'_>) -> PyResult<(u8, Vec<u8>)> {
        self.instance
            .bind(py)
            .call_method0("get_pairing_data")?
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
        self.setup_communication(py, pin)?;
        if let Ok((index, key)) = self.get_pairing_data(py) {
            save_pairing(&KeycardPairingData { index, key });
        }
        Ok(())
    }

    pub fn setup_communication(&self, py: Python<'_>, pin: &str) -> PyResult<bool> {
        self.instance
            .bind(py)
            .call_method1("setup_communication", (pin,))?
            .extract()
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

    pub fn get_account_id_for_path_with_connect(pin: &str, key_path: &str) -> PyResult<String> {
        let public_key = Self::get_public_key_for_path_with_connect(pin, key_path)?;

        Ok(format!("Public/{}", AccountId::from(&public_key)))
    }
}

fn pairing_file_path() -> Option<PathBuf> {
    let home = std::env::var("NSSA_WALLET_HOME_DIR")
        .map(PathBuf::from)
        .or_else(|_| {
            std::env::home_dir()
                .map(|h| h.join(".nssa").join("wallet"))
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
