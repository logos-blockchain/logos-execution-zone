use std::{env, path::PathBuf};

use pyo3::{prelude::*, types::PyList};

/// Adds the project's `python/` directory and venv site-packages to Python's sys.path
pub fn add_python_path(py: Python) -> PyResult<()> {
    let current_dir = env::current_dir().expect("Failed to get current working directory");

    let paths_to_add: Vec<PathBuf> = vec![
        current_dir.join("python"),
        current_dir.join("python").join("keycard-py"),
    ];

    // Sanity check — warns early if a path doesn't exist
    for path in &paths_to_add {
        if !path.exists() {
            eprintln!("Warning: Python path does not exist: {:?}", path);
        }
    }

    let sys = py.import_bound("sys")?;
    let sys_path: &PyList = sys.getattr("path")?.extract()?;

    for path in &paths_to_add {
        let path_str = path.to_str().expect("Invalid path");

        // Avoid duplicating the path
        if !sys_path
            .iter()
            .any(|p| p.extract::<&str>().unwrap_or("") == path_str)
        {
            sys_path.insert(0, path_str)?;
        }
    }

    Ok(())
}
