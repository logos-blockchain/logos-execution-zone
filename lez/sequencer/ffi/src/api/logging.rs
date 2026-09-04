use std::ffi::{CStr, c_char};

use log::LevelFilter;

/// Initializes logging for the sequencer at `level`.
///
/// - `level` is a null-terminated string (`off`/`error`/`warn`/`info`/`debug`/ `trace`,
///   case-insensitive); null or unparseable falls back to `info`.
///
/// Only the `sequencer_ffi` and `sequencer_core` targets are enabled!
///
/// # Safety
/// - `level` must be a valid null-terminated C string, or null.
/// - First call to this function wins; subsequent calls are no-ops.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn init_logger(level: *const c_char) {
    let level = if level.is_null() {
        LevelFilter::Info
    } else {
        unsafe { CStr::from_ptr(level) }
            .to_str()
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(LevelFilter::Info)
    };

    let _dontcare = env_logger::Builder::new()
        .filter_level(LevelFilter::Off)
        .filter_module("sequencer_ffi", level)
        .filter_module("sequencer_core", level)
        .try_init();
}
