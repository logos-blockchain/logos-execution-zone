use std::str::FromStr as _;

use keycard_rs::{
    KeycardCommandSet, PcscChannel,
    constants::sign_p2,
    parsing::Bip32KeyPair,
    secure_channel::SecureChannelVersion,
    tlv::{BerTlvReader, TLV_KEY_TEMPLATE, TLV_PUB_KEY, TLV_SIGNATURE_TEMPLATE},
};
use lee::{AccountId, PublicKey, Signature};
use rand::Rng as _;
use zeroize::Zeroizing;

/// LEE-applet extension tags. `keycard-rs` implements *sending* the LEE commands
/// (`load_lee_key`, `export_lee_key`) but never added parsing for their LEE-specific responses,
/// so these tag values — owned by the applet, not either client library — have to be hardcoded
/// here. Matches `KeycardApplet.TLV_LEE_NSK`/`TLV_LEE_VSK` in `status-keycard`
/// (`KeycardApplet.java:97-98`), the applet `LEE_keycard.cap` was almost certainly built from.
const TLV_LEE_NSK: u8 = 0x83;
const TLV_LEE_VSK: u8 = 0x84;
/// Raw Schnorr signature (64 bytes: `r || s`, no ASN.1/DER wrapping) nested inside the standard
/// `TLV_SIGNATURE_TEMPLATE` alongside the usual `TLV_PUB_KEY`. Confirmed against real hardware —
/// the LEE applet's `SIGN` response for `sign_p2::BIP340_SCHNORR` is
/// `0xA0 { 0x80 <65-byte pubkey>, 0x88 <64-byte r||s> }` — and matches
/// `SECP256k1.TLV_RAW_SIGNATURE` in `status-keycard` (`SECP256k1.java:64`).
const TLV_LEE_RAW_SIGNATURE: u8 = 0x88;

/// NSK (32 bytes) and VSK (64 bytes, the ML-KEM-768 seed `d || z`) as fixed-length zeroizing byte
/// arrays.
type PrivateKeyPair = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 64]>);

#[derive(Debug, thiserror::Error)]
pub enum KeycardWalletError {
    #[error(transparent)]
    Keycard(#[from] keycard_rs::Error),
    #[error("keycard is already initialized")]
    AlreadyInitialized,
    #[error(
        "this wallet only supports Secure Channel V2 keycards (applet version >= 4.0); detected {0:?}"
    )]
    UnsupportedSecureChannel(Option<SecureChannelVersion>),
    #[error("invalid mnemonic phrase: {0}")]
    InvalidMnemonic(String),
    #[error("invalid key material from keycard: {0}")]
    InvalidKeyMaterial(String),
    #[error("keycard returned a signature that does not verify against its own public key")]
    SignatureVerificationFailed,
    #[error("invalid KEYCARD_CA_PUBLIC_KEY: {0}")]
    InvalidCaPublicKey(String),
}

/// Rust wrapper around `keycard-rs`, talking to the LEE-flavored Keycard applet over PC/SC.
/// Only Secure Channel V2 cards are supported — see `require_secure_channel_v2`.
pub struct KeycardWallet {
    command_set: KeycardCommandSet,
}

impl KeycardWallet {
    /// Connects to the first available PC/SC reader. Does not select the applet yet — callers
    /// that need application info (`initialize`, `connect`, ...) do that themselves.
    ///
    /// Verifies the card's identity certificate against `keycard-rs`'s default production CA,
    /// unless overridden via `KEYCARD_CA_PUBLIC_KEY` — see `ca_public_key_override`.
    pub fn new() -> Result<Self, KeycardWalletError> {
        let channel = PcscChannel::connect()?;
        Ok(Self {
            command_set: Self::build_command_set(channel)?,
        })
    }

    fn build_command_set(channel: PcscChannel) -> Result<KeycardCommandSet, KeycardWalletError> {
        Ok(match ca_public_key_override()? {
            Some(ca) => KeycardCommandSet::new_with_ca(channel, ca),
            None => KeycardCommandSet::new(channel),
        })
    }

    /// Returns whether a smart card reader and a selectable, Secure-Channel-V2 Keycard are both
    /// present.
    #[must_use]
    pub fn is_keycard_available() -> bool {
        let Ok(channel) = PcscChannel::connect() else {
            return false;
        };
        let Ok(mut command_set) = Self::build_command_set(channel) else {
            return false;
        };
        if !command_set.select().is_ok_and(|resp| resp.is_ok()) {
            return false;
        }
        command_set.secure_channel_version() == Some(SecureChannelVersion::V2)
    }

    fn select(&mut self) -> Result<(), KeycardWalletError> {
        self.command_set.select()?.check_ok()?;
        Ok(())
    }

    /// Rejects any card that isn't running Secure Channel V2 (older applets, or a card that
    /// hasn't advertised a secure channel at all). Call right after `select()`.
    fn require_secure_channel_v2(&self) -> Result<(), KeycardWalletError> {
        match self.command_set.secure_channel_version() {
            Some(SecureChannelVersion::V2) => Ok(()),
            other => Err(KeycardWalletError::UnsupportedSecureChannel(other)),
        }
    }

    /// Rebuilds the PC/SC channel and command set, then retries `op` once, if `op` failed with a
    /// transport-level error (e.g. the card lost power mid-session).
    fn with_reconnect_on_transport_error<T>(
        &mut self,
        op: impl Fn(&mut Self) -> Result<T, KeycardWalletError>,
    ) -> Result<T, KeycardWalletError> {
        match op(self) {
            Err(KeycardWalletError::Keycard(keycard_rs::Error::Io(io_err))) => {
                log::warn!(
                    "transport error during keycard operation ({io_err}), reconnecting and retrying once"
                );
                *self = Self::new()?;
                op(self)
            }
            result => result,
        }
    }

    /// Initializes an uninitialized card, returning the generated PUK. The caller is responsible
    /// for surfacing the PUK to the operator — it cannot be recovered afterward.
    pub fn initialize(&mut self, pin: &str) -> Result<String, KeycardWalletError> {
        self.select()?;
        self.require_secure_channel_v2()?;
        let already_initialized = self
            .command_set
            .app_info()
            .expect("select() populates app_info on success")
            .is_initialized();
        if already_initialized {
            return Err(KeycardWalletError::AlreadyInitialized);
        }

        // V2's INIT has no shared-secret field (confirmed against real hardware and the
        // applet's own reference command set: a payload containing one is rejected outright) —
        // pass an empty secret and let the card default the PIN/PUK retry counts.
        let puk = generate_puk();
        self.command_set
            .init_with_secret(pin, None, &puk, &[], 0, 0)?
            .check_ok()?;
        Ok(puk)
    }

    /// Wipes the card's PIN, PUK, and loaded keys, returning it to an uninitialized state —
    /// the counterpart to `initialize()`. Does **not** remove the identity certificate
    /// provisioned via `IdentApplet`, so the card can be re-`initialize()`d afterward without
    /// re-personalizing it. Irreversibly destroys any keys currently loaded on the card.
    pub fn factory_reset(&mut self) -> Result<(), KeycardWalletError> {
        self.select()?;
        self.require_secure_channel_v2()?;
        self.command_set.factory_reset()?.check_ok()?;
        Ok(())
    }

    /// Opens the secure channel and verifies the PIN. Secure Channel V2 re-authenticates from
    /// the card's certificate every session — there's no pairing step and nothing to persist.
    pub fn connect(&mut self, pin: &str) -> Result<(), KeycardWalletError> {
        self.with_reconnect_on_transport_error(|wallet| {
            wallet.select()?;
            wallet.require_secure_channel_v2()?;
            wallet.command_set.auto_open_secure_channel()?;
            wallet.command_set.verify_pin(pin)?.check_auth_ok()?;
            Ok(())
        })
    }

    pub fn get_public_key_for_path(&mut self, path: &str) -> Result<PublicKey, KeycardWalletError> {
        let resp = self.command_set.export_key(path, false, true)?;
        resp.check_ok()?;
        let keypair = Bip32KeyPair::from_tlv(resp.data())?;

        // Uncompressed SEC1 point (0x04 || X || Y); the BIP340 x-only public key is just its X
        // coordinate, since secp256k1 (what the card signs with) and k256's Schnorr verifying key
        // are the same curve.
        let public_key = keypair.public_key();
        let x_only: [u8; 32] = match public_key.split_first() {
            Some((&0x04, xy)) if xy.len() == 64 => xy
                .split_at(32)
                .0
                .try_into()
                .expect("split_at(32) of a 64-byte slice"),
            _ => {
                return Err(KeycardWalletError::InvalidKeyMaterial(format!(
                    "expected a 65-byte uncompressed secp256k1 public key from keycard, got {} bytes",
                    public_key.len()
                )));
            }
        };

        PublicKey::try_new(x_only)
            .map_err(|e| KeycardWalletError::InvalidKeyMaterial(e.to_string()))
    }

    pub fn get_public_key_for_path_with_connect(
        pin: &str,
        path: &str,
    ) -> Result<PublicKey, KeycardWalletError> {
        let mut wallet = Self::new()?;
        wallet.connect(pin)?;
        wallet.get_public_key_for_path(path)
    }

    pub fn sign_message_for_path(
        &mut self,
        path: &str,
        message: &[u8; 32],
    ) -> Result<(Signature, PublicKey), KeycardWalletError> {
        let resp = self.command_set.sign_with_path_and_algo(
            message,
            path,
            sign_p2::BIP340_SCHNORR,
            false,
        )?;
        resp.check_ok()?;

        let sig = Signature {
            value: parse_schnorr_signature(resp.data())?,
        };
        let pub_key = self.get_public_key_for_path(path)?;
        if !sig.is_valid_for(message, &pub_key) {
            return Err(KeycardWalletError::SignatureVerificationFailed);
        }
        Ok((sig, pub_key))
    }

    pub fn sign_message_for_path_with_connect(
        pin: &str,
        path: &str,
        message: &[u8; 32],
    ) -> Result<(Signature, PublicKey), KeycardWalletError> {
        let mut wallet = Self::new()?;
        wallet.connect(pin)?;
        wallet.sign_message_for_path(path, message)
    }

    pub fn load_mnemonic(&mut self, mnemonic: &str) -> Result<(), KeycardWalletError> {
        let mnemonic = bip39::Mnemonic::from_str(mnemonic)
            .map_err(|e| KeycardWalletError::InvalidMnemonic(e.to_string()))?;
        let seed = mnemonic.to_seed("");
        self.command_set.load_lee_key(&seed)?.check_ok()?;
        Ok(())
    }

    pub fn get_public_account_id_for_path_with_connect(
        pin: &str,
        key_path: &str,
    ) -> Result<String, KeycardWalletError> {
        let public_key = Self::get_public_key_for_path_with_connect(pin, key_path)?;

        Ok(format!("Public/{}", AccountId::from(&public_key)))
    }

    pub fn get_private_keys_for_path(
        &mut self,
        path: &str,
    ) -> Result<PrivateKeyPair, KeycardWalletError> {
        let resp = self.command_set.export_lee_key(path)?;
        resp.check_ok()?;

        let mut reader = BerTlvReader::new(resp.data());
        reader.enter_constructed(TLV_KEY_TEMPLATE)?;
        let raw_nsk = reader.read_primitive(TLV_LEE_NSK)?;
        let raw_vsk = reader.read_primitive(TLV_LEE_VSK)?;

        let nsk = zeroizing_fixed_bytes::<32>("nullifier secret key", Zeroizing::new(raw_nsk))?;
        let vsk = zeroizing_fixed_bytes::<64>("view secret key", Zeroizing::new(raw_vsk))?;

        Ok((nsk, vsk))
    }

    pub fn get_private_keys_for_path_with_connect(
        pin: &str,
        path: &str,
    ) -> Result<PrivateKeyPair, KeycardWalletError> {
        let mut wallet = Self::new()?;
        wallet.connect(pin)?;
        wallet.get_private_keys_for_path(path)
    }
}

fn generate_puk() -> String {
    let mut rng = rand::rngs::OsRng;
    std::iter::repeat_with(|| char::from(rng.gen_range(b'0'..=b'9')))
        .take(12)
        .collect()
}

/// Optional override for the CA public key used to verify a card's identity certificate, read
/// from `KEYCARD_CA_PUBLIC_KEY` as 66 hex characters (a 33-byte compressed secp256k1 key).
/// Falls back to `keycard-rs`'s production default when unset.
///
/// This exists purely for testing against cards that weren't personalized through the real
/// production process — e.g. `status-keycard`'s own `JUnit` suite signs test cards with a fixed,
/// throwaway CA that will never match the production default. Real users' cards should need no
/// override at all.
fn ca_public_key_override() -> Result<Option<[u8; 33]>, KeycardWalletError> {
    let Ok(hex_str) = std::env::var("KEYCARD_CA_PUBLIC_KEY") else {
        return Ok(None);
    };
    let mut bytes = [0_u8; 33];
    hex::decode_to_slice(hex_str.trim(), &mut bytes)
        .map_err(|e| KeycardWalletError::InvalidCaPublicKey(e.to_string()))?;
    Ok(Some(bytes))
}

/// Parses a BIP340 Schnorr signature from a LEE `SIGN` response.
///
/// Confirmed against real hardware: `TLV_SIGNATURE_TEMPLATE` (0xA0) contains the usual
/// `TLV_PUB_KEY` (0x80, 65 bytes, unused here — the caller fetches the pubkey separately via
/// `export_key`) followed by `TLV_LEE_RAW_SIGNATURE` (0x88, 64 bytes: `r || s` with no ASN.1/DER
/// wrapping). `keycard-rs`'s own `RecoverableSignature` parser doesn't apply — it's ECDSA-only
/// (attempts point recovery, which Schnorr doesn't have).
fn parse_schnorr_signature(data: &[u8]) -> Result<[u8; 64], KeycardWalletError> {
    parse_schnorr_signature_inner(data).map_err(|e| {
        KeycardWalletError::InvalidKeyMaterial(format!(
            "failed to parse schnorr signature response ({e}); raw response bytes: {data:02x?}"
        ))
    })
}

fn parse_schnorr_signature_inner(data: &[u8]) -> Result<[u8; 64], KeycardWalletError> {
    let mut reader = BerTlvReader::new(data);
    reader.enter_constructed(TLV_SIGNATURE_TEMPLATE)?;
    if reader.next_tag_is(TLV_PUB_KEY) {
        reader.read_primitive(TLV_PUB_KEY)?;
    }
    let sig = reader.read_primitive(TLV_LEE_RAW_SIGNATURE)?;
    sig.try_into().map_err(|v: Vec<u8>| {
        KeycardWalletError::InvalidKeyMaterial(format!(
            "expected a 64-byte raw schnorr signature, got {} bytes",
            v.len()
        ))
    })
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Zeroizing<Vec<u8>> is consumed to ensure the source is zeroed on drop"
)]
fn zeroizing_fixed_bytes<const N: usize>(
    label: &str,
    raw: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<[u8; N]>, KeycardWalletError> {
    if raw.len() != N {
        return Err(KeycardWalletError::InvalidKeyMaterial(format!(
            "expected {N}-byte {label} from keycard, got {} bytes",
            raw.len()
        )));
    }
    let mut arr = Zeroizing::new([0_u8; N]);
    arr.copy_from_slice(&raw);
    Ok(arr)
}
