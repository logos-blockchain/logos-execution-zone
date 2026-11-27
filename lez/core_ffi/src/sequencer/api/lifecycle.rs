use std::{
    ffi::{CStr, c_char},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};

use sequencer_service::{DEFAULT_RPC_LISTEN_ADDRESS, StartArgs, ops::OpsServer};

use crate::{
    error::FfiOperationError,
    primitives::{result::PointerResult, runtime::Runtime, types::FfiBytes32},
    sequencer::SequencerServiceFFI,
};

pub type InitializedSequencerServiceFFIResult =
    PointerResult<SequencerServiceFFI, FfiOperationError>;

/// Overrides of what a sequencer starts with by default: `sequencer_service start`'s options
/// besides its home, each overriding the config the same way.
///
/// Every string is null-terminated UTF-8, and null keeps its default; zeroed, the struct overrides
/// nothing. Unlike `start`, no option falls back to a `SEQUENCER_*` env var.
#[repr(C)]
pub struct SequencerStartOverrides {
    /// Null for `<home>/sequencer_config.json`, the config `sequencer_service setup` writes; that
    /// one keeps its genesis, as `setup` decided.
    pub config: *const c_char,
    /// Keeps the genesis of `config`, so the channel is created if it does not exist. Needs
    /// `config`.
    pub create_channel: bool,
    /// Waits for the channel to be created, instead of failing, when it does not exist yet and
    /// this node has no genesis to create it with.
    pub wait_for_channel: bool,
    /// Null for `<home>/channel_signing_key`.
    pub channel_signing_key_file: *const c_char,
    /// In hex. Null for the one in `<home>/bedrock_funding_public_key`.
    pub funding_public_key: *const c_char,
    /// Overrides the config's `bedrock_config.node_url`.
    pub bedrock_node_url: *const c_char,
    /// In hex. Overrides the config's `bedrock_config.channel_id`.
    pub channel_id: *const c_char,
    /// `ip:port`. Null for `127.0.0.1:3040`. The RPC has no caller auth, so only widen it behind a
    /// firewall.
    pub rpc_listen_address: *const c_char,
    /// `ip:port` serving `/ping`, `/health` and `/metrics`. Overrides the config's
    /// `metrics_listen_address`.
    pub metrics_listen_address: *const c_char,
    /// Gossip's QUIC (UDP) `ip:port`. Turns gossip on if the config leaves it off.
    pub gossip_listen_addr: *const c_char,
    /// `gossip_bootstrap_peers_len` peers, each `host:port` or a multiaddr; null when the length
    /// is zero. Any peers replace the config's `bootstrap_peers`, and turn gossip on.
    pub gossip_bootstrap_peers: *const *const c_char,
    pub gossip_bootstrap_peers_len: usize,
}

/// Overrides nothing.
impl Default for SequencerStartOverrides {
    fn default() -> Self {
        Self {
            config: std::ptr::null(),
            create_channel: false,
            wait_for_channel: false,
            channel_signing_key_file: std::ptr::null(),
            funding_public_key: std::ptr::null(),
            bedrock_node_url: std::ptr::null(),
            channel_id: std::ptr::null(),
            rpc_listen_address: std::ptr::null(),
            metrics_listen_address: std::ptr::null(),
            gossip_listen_addr: std::ptr::null(),
            gossip_bootstrap_peers: std::ptr::null(),
            gossip_bootstrap_peers_len: 0,
        }
    }
}

impl SequencerStartOverrides {
    /// `start`'s options for `home` with these overrides.
    ///
    /// # Safety
    /// Every pointer must be null or valid as documented on the field.
    unsafe fn to_start_args(&self, home: PathBuf) -> Result<StartArgs, FfiOperationError> {
        let peers = if self.gossip_bootstrap_peers_len == 0 {
            &[][..]
        } else if self.gossip_bootstrap_peers.is_null() {
            tracing::error!("Null gossip_bootstrap_peers with a non-zero length");
            return Err(FfiOperationError::NullPointer);
        } else {
            // SAFETY: the caller guarantees the pointer covers `gossip_bootstrap_peers_len` peers.
            unsafe {
                std::slice::from_raw_parts(
                    self.gossip_bootstrap_peers,
                    self.gossip_bootstrap_peers_len,
                )
            }
        };
        let gossip_bootstrap_peer = peers
            .iter()
            .map(|&peer| {
                unsafe { optional_str(peer, "gossip_bootstrap_peers") }?.ok_or_else(|| {
                    tracing::error!("Null gossip bootstrap peer");
                    FfiOperationError::NullPointer
                })
            })
            .collect::<Result<_, _>>()?;

        Ok(StartArgs {
            home,
            config: unsafe { optional_str(self.config, "config") }?.map(PathBuf::from),
            create_channel: self.create_channel,
            wait_for_channel: self.wait_for_channel,
            channel_signing_key_file: unsafe {
                optional_str(self.channel_signing_key_file, "channel_signing_key_file")
            }?
            .map(PathBuf::from),
            funding_public_key: unsafe {
                optional_str(self.funding_public_key, "funding_public_key")
            }?,
            bedrock_node_url: unsafe { optional_str(self.bedrock_node_url, "bedrock_node_url") }?,
            channel_id: unsafe { optional_str(self.channel_id, "channel_id") }?,
            rpc_listen_address: unsafe {
                optional_addr(self.rpc_listen_address, "rpc_listen_address")
            }?
            .unwrap_or(DEFAULT_RPC_LISTEN_ADDRESS),
            metrics_listen_address: unsafe {
                optional_addr(self.metrics_listen_address, "metrics_listen_address")
            }?,
            gossip_listen_addr: unsafe {
                optional_addr(self.gossip_listen_addr, "gossip_listen_addr")
            }?,
            gossip_bootstrap_peer,
        })
    }
}

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

/// The `ip:port` `ptr` points to, or `None` when it is null.
///
/// # Safety
/// As for [`optional_str`].
unsafe fn optional_addr(
    ptr: *const c_char,
    name: &str,
) -> Result<Option<SocketAddr>, FfiOperationError> {
    unsafe { optional_str(ptr, name) }?
        .map(|addr| {
            addr.parse().map_err(|e| {
                tracing::error!(error = %e, "{name} is not an `ip:port`: {addr}");
                FfiOperationError::InvalidArgument
            })
        })
        .transpose()
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
/// - `config`: Path of the config to copy into it.
/// - `funding_public_key`: In hex, a funded key in the Bedrock node's wallet; it pays the node's
///   inscriptions.
/// - `create_channel`: Keeps the config's genesis, so starting creates the channel if it does not
///   exist.
/// - `out_channel_public_key`: Receives the channel signing public key, which is the key to stake;
///   null to skip it.
///
/// # Returns
///
/// `Success`; `NullPointer` or `InvalidUtf8` for a bad string; `ConfigError` when the home cannot
/// be set up: an unreadable or invalid config, an invalid funding key, or a home already set up.
///
/// # Safety
/// The caller must ensure that:
/// - `home`, `config` and `funding_public_key` are valid pointers to null-terminated UTF-8 strings.
/// - `out_channel_public_key` is null or a valid pointer to an `FfiBytes32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_setup(
    home: *const c_char,
    config: *const c_char,
    funding_public_key: *const c_char,
    create_channel: bool,
    out_channel_public_key: *mut FfiBytes32,
) -> FfiOperationError {
    let required = |ptr, name| {
        // SAFETY: the caller guarantees each argument is null or a valid C string.
        unsafe { optional_str(ptr, name) }?.ok_or_else(|| {
            tracing::error!("Attempted to give a null {name} pointer. This is a bug. Aborting.");
            FfiOperationError::NullPointer
        })
    };
    let (home, config, funding_public_key) = match (
        required(home, "home"),
        required(config, "config"),
        required(funding_public_key, "funding_public_key"),
    ) {
        (Ok(home), Ok(config), Ok(funding_public_key)) => (home, config, funding_public_key),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return e,
    };

    let set_up = std::fs::read_to_string(&config)
        .map_err(anyhow::Error::from)
        .and_then(|template| {
            sequencer_service::setup(
                home.as_ref(),
                &template,
                &funding_public_key,
                create_channel,
            )
        });
    match set_up {
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
/// `overrides` over its defaults.
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
/// - `overrides`: What to start with other than the defaults, see [`SequencerStartOverrides`]; null
///   for none.
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
/// - `overrides` is null or a valid pointer, whose own pointers are each null or valid as
///   documented.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_start_sequencer(
    runtime: *const Runtime,
    home: *const c_char,
    overrides: *const SequencerStartOverrides,
) -> InitializedSequencerServiceFFIResult {
    // SAFETY: The caller must ensure the validness of the pointer arguments.
    unsafe { setup_sequencer(runtime, home, overrides) }.map_or_else(
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
    overrides: *const SequencerStartOverrides,
) -> Result<SequencerServiceFFI, FfiOperationError> {
    // SAFETY: the caller guarantees `home` is a valid C string.
    let Some(home) = unsafe { optional_str(home, "home") }? else {
        tracing::error!("Attempted to give a null home pointer. This is a bug. Aborting.");
        return Err(FfiOperationError::NullPointer);
    };
    // SAFETY: the caller guarantees `overrides` is null or valid, and so are its pointers.
    let args = match unsafe { overrides.as_ref() } {
        Some(overrides) => unsafe { overrides.to_start_args(home.into()) }?,
        None => unsafe { SequencerStartOverrides::default().to_start_args(home.into()) }?,
    };

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
        let config = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../sequencer/service/networks/local.json"
        );
        let setup = |out: *mut FfiBytes32| unsafe {
            sequencer_ffi_setup(
                c_string(home.to_str().unwrap()).as_ptr(),
                c_string(config).as_ptr(),
                c_string(FUNDING_PUBLIC_KEY).as_ptr(),
                false,
                out,
            )
        };

        let mut channel_public_key = FfiBytes32::from([0; 32]);
        assert_eq!(
            setup(&raw mut channel_public_key),
            FfiOperationError::Success
        );

        // What `start` needs is all there: no explicit config, keys from the home.
        let args =
            unsafe { SequencerStartOverrides::default().to_start_args(home.clone()) }.unwrap();
        let loaded = args.load_config().unwrap();
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
            setup(std::ptr::null_mut()),
            FfiOperationError::ConfigError,
            "already set up"
        );
    }
}
