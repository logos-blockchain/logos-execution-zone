use std::{path::PathBuf, str::FromStr as _};

use keycard_rs::{
    KeycardCommandSet, PcscChannel,
    constants::sign_p2,
    parsing::Bip32KeyPair,
    secure_channel::Pairing,
    tlv::{BerTlvReader, TLV_KEY_TEMPLATE, TLV_PUB_KEY, TLV_SIGNATURE_TEMPLATE},
};
use lee::{AccountId, PublicKey, Signature};
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const DEFAULT_PAIRING_PASSWORD: &str = "KeycardDefaultPairing";

/// LEE-applet extension tags. These aren't part of upstream `keycard-rs`'s `tlv` module (which
/// only knows the standard Status Keycard tags) since they're specific to the LEE-flavored
/// applet (`LEE_keycard.cap`).
const TLV_LEE_NSK: u8 = 0x83;
const TLV_LEE_VSK: u8 = 0x84;
/// Raw Schnorr signature (64 bytes: `r || s`, no ASN.1/DER wrapping) nested inside the standard
/// `TLV_SIGNATURE_TEMPLATE` alongside the usual `TLV_PUB_KEY`. Confirmed against real hardware —
/// the LEE applet's `SIGN` response for `sign_p2::BIP340_SCHNORR` is
/// `0xA0 { 0x80 <65-byte pubkey>, 0x88 <64-byte r||s> }`.
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
    #[error("invalid mnemonic phrase: {0}")]
    InvalidMnemonic(String),
    #[error("invalid key material from keycard: {0}")]
    InvalidKeyMaterial(String),
    #[error("keycard returned a signature that does not verify against its own public key")]
    SignatureVerificationFailed,
}

// TODO: encrypt at rest alongside broader wallet storage encryption work.
#[derive(Serialize, Deserialize)]
pub struct KeycardPairingData {
    pub index: u8,
    pub key: Vec<u8>,
}

impl KeycardPairingData {
    const fn is_valid(&self) -> bool {
        self.key.len() == 32 && self.index <= 4
    }
}

/// Rust wrapper around `keycard-rs`, talking to the LEE-flavored Keycard applet over PC/SC.
pub struct KeycardWallet {
    command_set: KeycardCommandSet,
}

impl KeycardWallet {
    /// Connects to the first available PC/SC reader. Does not select the applet yet — callers
    /// that need application info (`initialize`, `pair`, `connect`, ...) do that themselves.
    pub fn new() -> Result<Self, KeycardWalletError> {
        let channel = PcscChannel::connect()?;
        Ok(Self {
            command_set: KeycardCommandSet::new(channel),
        })
    }

    /// Returns whether a smart card reader and a selectable Keycard are both present.
    #[must_use]
    pub fn is_unpaired_keycard_available() -> bool {
        let Ok(channel) = PcscChannel::connect() else {
            return false;
        };
        KeycardCommandSet::new(channel)
            .select()
            .is_ok_and(|resp| resp.is_ok())
    }

    fn select(&mut self) -> Result<(), KeycardWalletError> {
        self.command_set.select()?.check_ok()?;
        Ok(())
    }

    fn open_and_verify(&mut self, pin: &str) -> Result<(), KeycardWalletError> {
        self.command_set.auto_open_secure_channel()?;
        self.command_set.verify_pin(pin)?.check_auth_ok()?;
        Ok(())
    }

    /// Rebuilds the PC/SC channel and command set, then retries `op` once, if `op` failed with a
    /// transport-level error (e.g. the card lost power mid-session). Mirrors the reconnect-once
    /// behavior the previous `keycard-py`-based wallet had for `TransportError`.
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
        let already_initialized = self
            .command_set
            .app_info()
            .expect("select() populates app_info on success")
            .is_initialized();
        if already_initialized {
            return Err(KeycardWalletError::AlreadyInitialized);
        }

        let puk = generate_puk();
        self.command_set
            .init(pin, &puk, &pairing_password())?
            .check_ok()?;
        Ok(puk)
    }

    pub fn pair(&mut self, pin: &str) -> Result<(u8, [u8; 32]), KeycardWalletError> {
        self.select()?;
        self.command_set.auto_pair(&pairing_password())?;
        let pairing = self
            .command_set
            .pairing()
            .expect("auto_pair sets pairing data on success")
            .clone();

        if let Err(err) = self.open_and_verify(pin) {
            drop(self.command_set.auto_unpair());
            return Err(err);
        }

        Ok((pairing.pairing_index(), *pairing.pairing_key()))
    }

    pub fn setup_communication_with_pairing(
        &mut self,
        pin: &str,
        index: u8,
        key: &[u8; 32],
    ) -> Result<(), KeycardWalletError> {
        self.select()?;
        self.command_set.set_pairing(Pairing::new(*key, index));
        self.open_and_verify(pin)
    }

    /// Connect using a stored pairing if available, falling back to a fresh pair.
    /// Saves any newly established pairing to disk.
    pub fn connect(&mut self, pin: &str) -> Result<(), KeycardWalletError> {
        if let Some(pairing) = load_pairing().filter(KeycardPairingData::is_valid) {
            let key: [u8; 32] = pairing
                .key
                .clone()
                .try_into()
                .expect("KeycardPairingData::is_valid checked the key is 32 bytes");
            let reconnected = self.with_reconnect_on_transport_error(|wallet| {
                wallet.setup_communication_with_pairing(pin, pairing.index, &key)
            });
            if reconnected.is_ok() {
                return Ok(());
            }
        }

        let (index, key) = self.with_reconnect_on_transport_error(|wallet| wallet.pair(pin))?;
        save_pairing(&KeycardPairingData {
            index,
            key: key.to_vec(),
        });
        Ok(())
    }

    /// Unpairs the current session. Returns `false` if there was nothing to unpair.
    pub fn disconnect(&mut self) -> Result<bool, KeycardWalletError> {
        if self.command_set.pairing().is_none() {
            return Ok(false);
        }
        self.command_set.auto_unpair()?;
        Ok(true)
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

        PublicKey::try_new(x_only).map_err(|e| KeycardWalletError::InvalidKeyMaterial(e.to_string()))
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
        let resp =
            self.command_set
                .sign_with_path_and_algo(message, path, sign_p2::BIP340_SCHNORR, false)?;
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

    pub fn get_private_keys_for_path(&mut self, path: &str) -> Result<PrivateKeyPair, KeycardWalletError> {
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
        let result = wallet.get_private_keys_for_path(path);
        drop(wallet.disconnect());
        result
    }
}

fn generate_puk() -> String {
    let mut rng = rand::rngs::OsRng;
    std::iter::repeat_with(|| char::from(rng.gen_range(b'0'..=b'9')))
        .take(12)
        .collect()
}

fn pairing_password() -> String {
    std::env::var("KEYCARD_PAIRING_PASSWORD").unwrap_or_else(|_| DEFAULT_PAIRING_PASSWORD.to_owned())
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

fn pairing_file_path() -> Option<PathBuf> {
    let home = std::env::var("LEE_WALLET_HOME_DIR")
        .map(PathBuf::from)
        .or_else(|_| {
            std::env::home_dir()
                .map(|h| h.join(".lee").join("wallet"))
                .ok_or(())
        })
        .ok()?;
    Some(home.join("keycard_pairing.json"))
}

fn load_pairing() -> Option<KeycardPairingData> {
    let path = pairing_file_path()?;
    let file = std::fs::File::open(path).ok()?;
    serde_json::from_reader(file).ok()
}

fn save_pairing(data: &KeycardPairingData) {
    if let Some(path) = pairing_file_path()
        && let Ok(json) = serde_json::to_vec_pretty(data)
    {
        drop(std::fs::write(path, json));
    }
}

pub fn clear_pairing() {
    if let Some(path) = pairing_file_path() {
        drop(std::fs::remove_file(path));
    }
}
