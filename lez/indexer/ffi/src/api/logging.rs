use std::ffi::{CStr, c_char};

use logging::EnvFilter;
use tracing::level_filters::LevelFilter;

/// Initializes logging for the indexer at `level`.
///
/// - `level` is a null-terminated string (`off`/`error`/`warn`/`info`/`debug`/ `trace`,
///   case-insensitive); null or unparseable falls back to `info`.
///
/// `RUST_LOG`, when set, overrides `level` (e.g. `info,indexer_core=debug`).
///
/// # Safety
/// - `level` must be a valid null-terminated C string, or null.
/// - First call to this function wins; subsequent calls are no-ops.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn init_logger(level: *const c_char) {
    let level = if level.is_null() {
        LevelFilter::INFO
    } else {
        unsafe { CStr::from_ptr(level) }
            .to_str()
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(LevelFilter::INFO)
    };

    let _dontcare = logging::try_init_with_filter(
        EnvFilter::builder()
            .with_default_directive(level.into())
            .from_env_lossy(),
    );
}
