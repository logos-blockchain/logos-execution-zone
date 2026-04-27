use nssa::{AccountId, PublicKey, Signature};
use pyo3::{prelude::*, types::PyAny};

pub mod python_path;

/// Rust wrapper around the Python `KeycardWallet` class.
pub struct KeycardWallet {
    instance: Py<PyAny>,
}

impl KeycardWallet {
    /// Create a new Python `KeycardWallet` instance.
    pub fn new(py: Python) -> PyResult<Self> {
        let module = py.import_bound("keycard_wallet")?;
        let class = module.getattr("KeycardWallet")?;

        let instance = class.call0()?;

        Ok(Self {
            instance: instance.into_py(py),
        })
    }

    pub fn is_unpaired_keycard_available(&self, py: Python) -> PyResult<bool> {
        self.instance
            .bind(py)
            .call_method0("is_unpaired_keycard_available")?
            .extract()
    }

    pub fn setup_communication(&self, py: Python, pin: &str) -> PyResult<bool> {
        let py_pin = pyo3::types::PyString::new_bound(py, pin);

        self.instance
            .bind(py)
            .call_method1("setup_communication", (py_pin,))?
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

        let public_key: [u8; 32] = public_key.try_into().expect("Expect 32 bytes");

        Ok(PublicKey::try_new(public_key).expect("Expect a valid public key1"))
    }

    #[must_use]
    pub fn get_public_key_for_path_with_connect(pin: &str, path: &str) -> PublicKey {
        let pub_key = Python::with_gil(|py| {
            python_path::add_python_path(py).expect("keycard_wallet.py not found");

            let wallet = Self::new(py).expect("Expect keycard wallet");

            let is_connected = wallet
                .setup_communication(py, pin)
                .expect("Expect a Boolean.");

            if is_connected {
                println!("\u{2705} Keycard is now connected to wallet.");
            } else {
                println!("\u{274c} Keycard is not connected to wallet.");
            }

            let pub_key = wallet.get_public_key_for_path(py, path);

            let _ = wallet.disconnect(py);
            pub_key
        });
        pub_key.expect("Expect a valid public key2")
    }

    pub fn sign_message_for_path(
        &self,
        py: Python,
        path: &str,
        message: &[u8; 32],
    ) -> PyResult<Signature> {
        let py_message = pyo3::types::PyBytes::new_bound(py, message);

        let py_signature: Vec<u8> = self
            .instance
            .bind(py)
            .call_method1("sign_message_for_path", (py_message, path))?
            .extract()?;

        let signature: [u8; 64] = py_signature.try_into().map_err(|_| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Expected signature of exactly 64 bytes",
            )
        })?;
        println!("{signature:?}");
        Ok(Signature { value: signature })
    }

    #[must_use]
    pub fn sign_message_for_path_with_connect(
        pin: &str,
        path: &str,
        message: &[u8; 32],
    ) -> PyResult<Signature> {
        Python::with_gil(|py| {
            python_path::add_python_path(py).expect("keycard_wallet.py not found");

            let wallet = Self::new(py).expect("Expect keycard wallet");

            let is_connected = wallet
                .setup_communication(py, pin)
                .expect("Expect a Boolean.");

            if is_connected {
                println!("\u{2705} Keycard is now connected to wallet.");
            } else {
                println!("\u{274c} Keycard is not connected to wallet.");
            }

            let signature = wallet.sign_message_for_path(py, path, message);

            let _ = wallet.disconnect(py);

            signature
        })
    }

    pub fn load_mnemonic(&self, py: Python, mnemonic: &str) -> PyResult<()> {
        self.instance
            .bind(py)
            .call_method1("load_mnemonic", (mnemonic,))?;
        Ok(())
    }

    #[must_use]
    pub fn get_account_id_for_path_with_connect(pin: &str, key_path: &str) -> String {
        let public_key = Self::get_public_key_for_path_with_connect(pin, key_path);

        format!("Public/{}", AccountId::from(&public_key))
    }
}
