use nssa::{AccountId, PublicKey, Signature};
use nssa_core::NullifierPublicKey;
use pyo3::{prelude::*, types::PyAny};

pub mod python_path;

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

            let is_connected = wallet.setup_communication(py, pin)?;

            if is_connected {
                log::info!("\u{2705} Keycard is now connected to wallet.");
            } else {
                log::info!("\u{274c} Keycard is not connected to wallet.");
            }

            let pub_key = wallet.get_public_key_for_path(py, path);

            drop(wallet.disconnect(py));
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

            let is_connected = wallet.setup_communication(py, pin)?;

            if is_connected {
                log::info!("\u{2705} Keycard is now connected to wallet.");
            } else {
                log::info!("\u{274c} Keycard is not connected to wallet.");
            }

            let result = wallet.sign_message_for_path(py, path, message);

            drop(wallet.disconnect(py));

            result
        })
    }

    pub fn load_mnemonic(&self, py: Python, mnemonic: &str) -> PyResult<()> {
        self.instance
            .bind(py)
            .call_method1("load_mnemonic", (mnemonic,))?;
        Ok(())
    }

    pub fn get_public_account_id_for_path_with_connect(pin: &str, key_path: &str) -> PyResult<String> {
        let public_key = Self::get_public_key_for_path_with_connect(pin, key_path)?;

        Ok(format!("Public/{}", AccountId::from(&public_key)))
    }

    pub fn get_private_keys_for_path(
        &self,
        py: Python,
        path: &str,
    ) -> PyResult<([u8; 32], [u8; 32])> {
        let (raw_nsk, raw_vsk): (Vec<u8>, Vec<u8>) = self
            .instance
            .bind(py)
            .call_method1("get_private_keys_for_path", (path,))?
            .extract()?;

        let nsk: [u8; 32] = raw_nsk.try_into().map_err(|vec: Vec<u8>| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "expected 32-byte NSK from keycard, got {} bytes",
                vec.len()
            ))
        })?;

        let vsk: [u8; 32] = raw_vsk.try_into().map_err(|vec: Vec<u8>| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "expected 32-byte VSK from keycard, got {} bytes",
                vec.len()
            ))
        })?;

        Ok((nsk, vsk))
    }

    pub fn get_private_keys_for_path_with_connect(
        pin: &str,
        path: &str,
    ) -> PyResult<([u8; 32], [u8; 32])> {
        Python::with_gil(|py| {
            python_path::add_python_path(py)?;

            let wallet = Self::new(py)?;

            let is_connected = wallet.setup_communication(py, pin)?;

            if is_connected {
                log::info!("\u{2705} Keycard is now connected to wallet.");
            } else {
                log::info!("\u{274c} Keycard is not connected to wallet.");
            }

            let result = wallet.get_private_keys_for_path(py, path);

            drop(wallet.disconnect(py));
            result
        })
    }

    pub fn get_private_account_id_for_path_with_connect(pin: &str, key_path: &str) -> PyResult<String> {
        let (nsk, _vsk) = Self::get_private_keys_for_path_with_connect(pin, key_path)?;
        let npk = NullifierPublicKey::from(&nsk);

        Ok(format!("Private/{}", AccountId::from((&npk, 0_u128))))
    }
}
