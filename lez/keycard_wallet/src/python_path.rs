use std::{env, path::PathBuf};

use pyo3::{prelude::*, types::PyList};

fn collect_python_paths() -> Vec<PathBuf> {
    let current_dir = env::current_dir().expect("Failed to get current working directory");

    let python_base = env::var("VIRTUAL_ENV")
        .ok()
        .and_then(|v| PathBuf::from(v).parent().map(PathBuf::from))
        .unwrap_or_else(|| current_dir.clone());

    let mut paths = vec![
        python_base
            .join("lez")
            .join("keycard_wallet")
            .join("python"),
        python_base
            .join("lez")
            .join("keycard_wallet")
            .join("python")
            .join("keycard-py"),
    ];

    // pyo3's embedded interpreter does not inherit sys.path from the shell,
    // so venv site-packages must be added explicitly.
    if let Ok(venv) = env::var("VIRTUAL_ENV") {
        let lib = PathBuf::from(&venv).join("lib");
        if let Ok(entries) = std::fs::read_dir(&lib) {
            for entry in entries.flatten() {
                let site_packages = entry.path().join("site-packages");
                if site_packages.exists() {
                    paths.push(site_packages);
                }
            }
        }
    }

    paths
}

/// Adds the project's `python/` directory and venv site-packages to Python's sys.path.
pub fn add_python_path(py: Python<'_>) -> PyResult<()> {
    let paths = collect_python_paths();

    for path in &paths {
        if !path.exists() {
            log::info!("Warning: Python path does not exist: {}", path.display());
        }
    }

    let sys = PyModule::import(py, "sys")?;
    let binding = sys.getattr("path")?;
    let sys_path = binding.cast::<PyList>()?;

    for path in &paths {
        let path_str = path.to_str().expect("Invalid path");

        let already_present = sys_path
            .iter()
            .any(|p| p.extract::<&str>().is_ok_and(|s| s == path_str));

        if !already_present {
            sys_path.insert(0, path_str)?;
        }
    }

    Ok(())
}
