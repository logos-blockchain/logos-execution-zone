use pyo3::prelude::*;
use pyo3::types::PyAny;

/// Rust wrapper around the Python KeycardWallet class.
/// Holds a persistent Python object in memory.
pub struct KeycardWallet {
    instance: Py<PyAny>,
}

impl KeycardWallet {
    /// Create a new Python KeycardWallet instance
    pub fn new(py: Python) -> PyResult<Self> {
        let module = py.import_bound("keycard_wallet")?;
        let class = module.getattr("KeycardWallet")?;

        let instance = class.call0()?;

        Ok(Self {
            instance: instance.into_py(py),
        })
    }

    /// Calls Python: is_unpaired_keycard_available()
    pub fn is_unpaired_keycard_available(&self, py: Python) -> PyResult<bool> {
        self.instance
            .bind(py)
            .call_method0("is_unpaired_keycard_available")?
            .extract()
    }

    pub fn setup_communication(&self, py: Python, pin: String) -> PyResult<bool> {
        let py_pin = pyo3::types::PyString::new_bound(py, &pin);

        self.instance
            .bind(py)
            .call_method1("setup_communication", (py_pin,))?
            .extract()
    }

    pub fn disconnect(&self, py: Python) -> PyResult<bool> {
        self.instance
            .bind(py)
            .call_method0("disconnect")?
            .extract()
    }

    fn convert_path_to_string(path: Vec<u32>) -> String {
        format!(
            "m/{}",
            path.iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join("'/")
        )
    }

    pub fn get_public_key_for_path(
        &self,
        py: Python,
        path: &str,
    ) -> PyResult<Option<[u8;32]>> {
        let public_key: Vec<u8> = self.instance
            .bind(py)
            .call_method1("get_public_key_for_path", (py_message, path))?
            .getattr("public_key")?
            .extract()?;

        Ok(Some(public_key.bytes()))
    }   

    pub fn sign_message_with_path(&self, py: Python, path: Vec<u32>, message: &[u8; 32]) -> PyResult<[u8; 64]> {
        let py_message = pyo3::types::PyBytes::new_bound(py, message);
        let path = Self::convert_path_to_string(path);
        
        let py_signature: Vec<u8> = self.instance
            .bind(py)
            .call_method1("sign_message_with_path", (py_message, path))?
            .getattr("signature")?
            .extract()?;

        let signature: [u8; 64] = py_signature
            .try_into()
            .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Expected signature of exactly 64 bytes"
            ))?;

        Ok(signature)
    }

    pub fn load_mnemonic(&self, py: Python, mnemonic: &str) -> PyResult<()> {
        self.instance
            .bind(py)
            .call_method1("load_mnemonic", (mnemonic,))?;
        Ok(())
    }
}