use std::{env, path::PathBuf};

use pyo3::{prelude::*, types::PyList};

/// Adds the project's `python/` directory and venv site-packages to Python's sys.path.
pub fn add_python_path(py: Python<'_>) -> PyResult<()> {
    let current_dir = env::current_dir().expect("Failed to get current working directory");

    let paths_to_add: Vec<PathBuf> = vec![
        current_dir.join("python"),
        current_dir.join("python").join("keycard-py"),
    ];

    // Sanity check — warns early if a path doesn't exist
    for path in &paths_to_add {
        if !path.exists() {
            log::info!("Warning: Python path does not exist: {}", path.display());
        }
    }

    let sys = PyModule::import(py, "sys")?;
    let binding = sys.getattr("path")?;
    let sys_path = binding.downcast::<PyList>()?;

    for path in &paths_to_add {
        let path_str = path.to_str().expect("Invalid path");

        // Avoid duplicating the path
        let already_present = sys_path
            .iter()
            .any(|p| p.extract::<&str>().map(|s| s == path_str).unwrap_or(false));

        if !already_present {
            sys_path.insert(0, path_str)?;
        }
    }

    Ok(())
}
