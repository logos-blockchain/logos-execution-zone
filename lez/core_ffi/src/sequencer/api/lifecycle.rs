use std::{
    ffi::{CStr, c_char},
    sync::Arc,
};

use sequencer_service::{SetupArgs, StartArgs, ops::OpsServer};

use crate::{
    error::FfiOperationError,
    primitives::{result::PointerResult, runtime::Runtime, types::FfiBytes32},
    sequencer::SequencerServiceFFI,
};

pub type InitializedSequencerServiceFFIResult =
    PointerResult<SequencerServiceFFI, FfiOperationError>;

/// The string `ptr` points to, or `None` when it is null.
///
/// # Safety
/// `ptr` must be null or point to a null-terminated string.
unsafe fn optional_str(
    ptr: *const c_char,
    name: &str,
) -> Result<Option<String>, FfiOperationError> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: the caller guarantees `ptr` is a valid C string.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map(|s| Some(s.to_owned()))
        .map_err(|e| {
            tracing::error!(error = %e, "{name} is not valid UTF-8");
            FfiOperationError::InvalidUtf8
        })
}

/// Prepares `home` for [`sequencer_ffi_start_sequencer`] the way `sequencer_service setup` does:
/// creates it with its config, channel signing key and Bedrock funding public key.
///
/// The config is the one at `config` with `home` filled in, keeping its genesis only with
/// `create_channel`. An existing channel signing key is kept, as it may already be staked. A home
/// that is already set up is refused.
///
/// # Arguments
///
/// - `home`: The home to create.
/// - `args_json`: `setup`'s options as a JSON object:
///   - `config`: Path of the config to copy into the home.
///   - `funding_public_key`: In hex, a funded key in the Bedrock node's wallet; it pays the node's
///     inscriptions.
///   - `create_channel` (optional, `false`): Keeps the config's genesis, so starting creates the
///     channel if it does not exist.
/// - `out_channel_public_key`: Receives the channel signing public key, which is the key to stake;
///   null to skip it.
///
/// # Returns
///
/// `Success`; `NullPointer` or `InvalidUtf8` for a bad string; `InvalidArgument` for `args_json`
/// that is not an object of those fields; `ConfigError` when the home cannot be set up: an
/// unreadable or invalid config, an invalid funding key, or a home already set up.
///
/// # Safety
/// The caller must ensure that:
/// - `home` and `args_json` are valid pointers to null-terminated UTF-8 strings.
/// - `out_channel_public_key` is null or a valid pointer to an `FfiBytes32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_setup(
    home: *const c_char,
    args_json: *const c_char,
    out_channel_public_key: *mut FfiBytes32,
) -> FfiOperationError {
    let required = |ptr, name| {
        // SAFETY: the caller guarantees each argument is null or a valid C string.
        unsafe { optional_str(ptr, name) }?.ok_or_else(|| {
            tracing::error!("Attempted to give a null {name} pointer. This is a bug. Aborting.");
            FfiOperationError::NullPointer
        })
    };
    let (home, args_json) = match (required(home, "home"), required(args_json, "args_json")) {
        (Ok(home), Ok(args_json)) => (home, args_json),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    let args: SetupArgs = match serde_json::from_str(&args_json) {
        Ok(args) => args,
        Err(e) => {
            tracing::error!(error = %e, "Invalid sequencer setup args");
            return FfiOperationError::InvalidArgument;
        }
    };

    match args.run(home.as_ref()) {
        Ok(set_up) => {
            // SAFETY: the caller guarantees `out_channel_public_key` is null or valid.
            if let Some(out) = unsafe { out_channel_public_key.as_mut() } {
                *out = set_up.channel_public_key.to_bytes().into();
            }
            FfiOperationError::Success
        }
        Err(e) => {
            tracing::error!(
                error = format_args!("{e:#}"),
                "Failed to set up the sequencer home"
            );
            FfiOperationError::ConfigError
        }
    }
}

/// Creates and starts a sequencer out of `home` the way `sequencer_service start` does, with
/// `overrides_json` over its defaults.
///
/// That includes serving the RPC on `rpc_listen_address`, and `/ping`, `/health` and `/metrics` on
/// the metrics address.
///
/// Blocks until the sequencer has started, which with `wait_for_channel` lasts until the channel
/// exists.
///
/// # Arguments
///
/// - `runtime`: A runtime for the sequencer to run on, or null to have the sequencer create and own
///   one.
/// - `home`: The sequencer's home: it holds the database, and by default the config
///   (`<home>/sequencer_config.json`) and keys.
/// - `overrides_json`: `start`'s other options as a JSON object of their names, each left out
///   taking its default: `config` (null for `<home>/sequencer_config.json`, the config `setup`
///   wrote), `create_channel`, `wait_for_channel`, `channel_signing_key_file`,
///   `funding_public_key`, `bedrock_node_url`, `channel_id`, `rpc_listen_address` (`127.0.0.1:3040`
///   unless given), `metrics_listen_address`, `gossip_listen_addr` and `gossip_bootstrap_peers` (an
///   array). See `sequencer_service start --help`. Unlike `start`, no option falls back to a
///   `SEQUENCER_*` env var. Null or empty for no overrides; anything else is refused with
///   `InvalidArgument`.
///
/// # Returns
///
/// An `InitializedSequencerServiceFFIResult` containing either a pointer to the
/// initialized `SequencerServiceFFI` or an error code.
///
/// # Safety
/// The caller must ensure that:
/// - `runtime` is either null or a valid pointer to a [`Runtime`] that outlives the sequencer.
/// - `home` is a valid pointer to a null-terminated UTF-8 string.
/// - `overrides_json` is null or a valid pointer to a null-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_start_sequencer(
    runtime: *const Runtime,
    home: *const c_char,
    overrides_json: *const c_char,
) -> InitializedSequencerServiceFFIResult {
    // SAFETY: The caller must ensure the validness of the pointer arguments.
    unsafe { setup_sequencer(runtime, home, overrides_json) }.map_or_else(
        InitializedSequencerServiceFFIResult::from_error,
        InitializedSequencerServiceFFIResult::from_value,
    )
}

/// Use the caller's runtime if one was supplied, otherwise create (and own)
/// our own. The `Runtime` wrapper drops the underlying tokio runtime only
/// when we own it; a borrowed one is left to its external owner.
///
/// # Safety
/// `runtime` must be null or a valid pointer to a [`Runtime`] that outlives the sequencer.
unsafe fn runtime_or_new(runtime: *const Runtime) -> Result<Runtime, FfiOperationError> {
    if runtime.is_null() {
        Runtime::new().map_err(|e| {
            tracing::error!(error = %e, "Could not create tokio runtime");
            FfiOperationError::SequencerInitializationError
        })
    } else {
        // SAFETY: the caller guarantees `runtime` is valid and outlives the sequencer.
        let caller = unsafe { &*runtime };
        Ok(unsafe { Runtime::from_borrowed(caller.as_ref()) })
    }
}

/// See [`sequencer_ffi_start_sequencer`].
///
/// # Safety
/// As for [`sequencer_ffi_start_sequencer`].
unsafe fn setup_sequencer(
    runtime: *const Runtime,
    home: *const c_char,
    overrides_json: *const c_char,
) -> Result<SequencerServiceFFI, FfiOperationError> {
    // SAFETY: the caller guarantees `home` is a valid C string.
    let Some(home) = unsafe { optional_str(home, "home") }? else {
        tracing::error!("Attempted to give a null home pointer. This is a bug. Aborting.");
        return Err(FfiOperationError::NullPointer);
    };
    // SAFETY: the caller guarantees `overrides_json` is null or a valid C string.
    let overrides = unsafe { optional_str(overrides_json, "overrides_json") }?.unwrap_or_default();
    let args = StartArgs::from_json(home.into(), &overrides).map_err(|e| {
        tracing::error!(
            error = format_args!("{e:#}"),
            "Invalid sequencer start overrides"
        );
        FfiOperationError::InvalidArgument
    })?;

    let start = || -> anyhow::Result<_> {
        let config = args.load_config()?;
        let public_key = sequencer_service::channel_public_key(&config)?;
        Ok((config, public_key))
    };
    let (config, public_key) = start().map_err(|e| {
        tracing::error!(
            error = format_args!("{e:#}"),
            "Failed to load the sequencer config"
        );
        FfiOperationError::SequencerInitializationError
    })?;

    // SAFETY: the caller guarantees `runtime` is null or valid and outlives the sequencer.
    let runtime = unsafe { runtime_or_new(runtime) }?;

    let (handle, ops) = runtime
        .block_on(async move {
            // Served from the start, so probes and metrics answer while startup waits on Bedrock.
            let ops = OpsServer::start(config.metrics_listen_address, &public_key).await?;
            match sequencer_service::run(config, args.rpc_listen_address).await {
                Ok(handle) => {
                    let handle = Arc::new(handle);
                    if let Some(ops) = &ops {
                        ops.set_sequencer(&handle);
                    }
                    Ok((handle, ops))
                }
                Err(err) => {
                    if let Some(ops) = ops {
                        ops.stop().await;
                    }
                    Err(err)
                }
            }
        })
        .map_err(|e| {
            tracing::error!(
                error = format_args!("{e:#}"),
                "Could not start the sequencer"
            );
            FfiOperationError::SequencerInitializationError
        })?;

    Ok(SequencerServiceFFI::new(handle, ops, runtime))
}

/// Whether every task of the sequencer is still running, as its `/health` reports.
///
/// Gossip is not part of it: without gossip the node keeps running on L1 alone. A sequencer that
/// is no longer healthy stays so; stop it and start a new one.
///
/// # Safety
/// `sequencer` must be a valid pointer to a `SequencerServiceFFI` created by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_is_healthy(sequencer: *const SequencerServiceFFI) -> bool {
    // SAFETY: the caller guarantees `sequencer` is null or valid.
    unsafe { sequencer.as_ref() }.map_or_else(
        || {
            tracing::error!("Attempted to query a null sequencer pointer. This is a bug.");
            false
        },
        SequencerServiceFFI::is_healthy,
    )
}

/// Stops and frees the resources associated with the given sequencer service.
///
/// # Arguments
///
/// - `sequencer`: A pointer to the `SequencerServiceFFI` instance to be stopped.
///
/// # Returns
///
/// An `OperationStatus` indicating success or failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `sequencer` is a valid pointer to a `SequencerServiceFFI` instance
/// - The `SequencerServiceFFI` instance was created by this library
/// - The pointer will not be used after this function returns
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_stop_sequencer(
    sequencer: *mut SequencerServiceFFI,
) -> FfiOperationError {
    if sequencer.is_null() {
        tracing::error!("Attempted to stop a null sequencer pointer. This is a bug. Aborting.");
        return FfiOperationError::NullPointer;
    }

    let sequencer = unsafe { Box::from_raw(sequencer) };

    drop(sequencer);

    FfiOperationError::Success
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    /// `docker-compose.yml`'s default funding key.
    const FUNDING_PUBLIC_KEY: &str =
        "2e03b2eff5a45478e7e79668d2a146cf2c5c7925bce927f2b1c67f2ab4fc0d26";

    fn c_string(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn setup_prepares_a_home_start_accepts() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        // `local.json` without its `home`: setup and start supply that themselves.
        let mut template: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../sequencer/service/networks/local.json"
        ))
        .unwrap();
        template.as_object_mut().unwrap().remove("home").unwrap();
        let config = dir.path().join("config.json");
        std::fs::write(&config, template.to_string()).unwrap();
        let args =
            serde_json::json!({ "config": config, "funding_public_key": FUNDING_PUBLIC_KEY })
                .to_string();
        let setup = |args_json: &str, out: *mut FfiBytes32| unsafe {
            sequencer_ffi_setup(
                c_string(home.to_str().unwrap()).as_ptr(),
                c_string(args_json).as_ptr(),
                out,
            )
        };

        let mut channel_public_key = FfiBytes32::from([0; 32]);
        assert_eq!(
            setup(&args, &raw mut channel_public_key),
            FfiOperationError::Success
        );

        // What `start` needs is all there: no explicit config, keys from the home.
        let loaded = StartArgs::from_json(home.clone(), "")
            .unwrap()
            .load_config()
            .unwrap();
        assert!(
            loaded.genesis.is_none(),
            "a joiner's home drops the genesis"
        );
        assert_eq!(
            FfiBytes32::from(
                sequencer_service::channel_public_key(&loaded)
                    .unwrap()
                    .to_bytes()
            ),
            channel_public_key
        );

        assert_eq!(
            setup(&args, std::ptr::null_mut()),
            FfiOperationError::ConfigError,
            "already set up"
        );
        assert_eq!(
            setup(
                r#"{"config": "c", "funding_public_key": "f", "extra": 1}"#,
                std::ptr::null_mut()
            ),
            FfiOperationError::InvalidArgument,
            "unknown field"
        );
    }

    #[test]
    fn start_overrides_parse_like_start_options() {
        let args = StartArgs::from_json(
            "/seq".into(),
            r#"{"config": "/etc/seq.json", "create_channel": true, "metrics_listen_address": null,
                "rpc_listen_address": "0.0.0.0:3040", "gossip_bootstrap_peers": ["a:1", "b:2"]}"#,
        )
        .unwrap();
        assert_eq!(args.home, std::path::Path::new("/seq"));
        assert_eq!(
            args.config.as_deref(),
            Some(std::path::Path::new("/etc/seq.json"))
        );
        assert!(args.create_channel && !args.wait_for_channel);
        assert_eq!(args.rpc_listen_address.to_string(), "0.0.0.0:3040");
        assert_eq!(args.metrics_listen_address, None);
        assert_eq!(args.gossip_bootstrap_peer, ["a:1", "b:2"]);

        let defaults = StartArgs::from_json("/seq".into(), "").unwrap();
        assert_eq!(
            defaults.rpc_listen_address,
            sequencer_service::DEFAULT_RPC_LISTEN_ADDRESS
        );
        assert!(defaults.config.is_none() && defaults.gossip_bootstrap_peer.is_empty());

        for bad in [
            r#"{"home": "/elsewhere"}"#,
            r#"{"nope": 1}"#,
            r#"{"create_channel": "yes"}"#,
            "[]",
        ] {
            assert!(StartArgs::from_json("/seq".into(), bad).is_err(), "{bad}");
        }
    }
}
