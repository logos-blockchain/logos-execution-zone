//! Paying a `.lez` name: resolving it through an LNS (Logos Names) registry to the
//! private receiving keys, or the public account, its holder published.
//!
//! The chain never sees a name. A name is turned into an identifier and a key on
//! this side; the registry keeps, at an address derived from the identifier, a
//! record whose profile is sealed under the key. Specification:
//! <https://github.com/jefdiesel/logos-names/blob/main/SPEC.md>.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use anyhow::{Context as _, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use borsh::BorshDeserialize;
use lee_core::{
    NullifierPublicKey, PrivateAccountKind,
    account::{AccountId, Actor},
    encryption::ViewingPublicKey,
    program::PdaSeed,
};
use sha2::{Digest as _, Sha256};

use crate::{AccountIdentity, WalletCore};

/// One fixed salt for every network: a name keeps its identifier and key from
/// testnet to mainnet.
const MASTER_SALT: &[u8] = b"logos-names/v5";
/// Argon2id memory in KiB (64 MiB), passes and lanes.
const MASTER_MEMORY_KIB: u32 = 65_536;
const MASTER_PASSES: u32 = 3;
const MASTER_LANES: u32 = 1;
const ID_DOMAIN: &[u8] = b"logos-names/v5/id";
const KEY_DOMAIN: &[u8] = b"logos-names/v5/key";
const RECORD_SEED_DOMAIN: &[u8] = b"logos-names/v5/name/";
const RECORD_ASSOCIATED_DATA: &[u8] = b"logos-names/v5/record";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// A lapsed name still resolves for this long, then anyone may register it.
const GRACE_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const SUFFIX: &str = ".lez";

/// The on-chain record of a name.
#[derive(Debug, BorshDeserialize)]
struct NameRecord {
    _version: u8,
    _owner_tag: [u8; 32],
    expires: u64,
    sealed: Vec<u8>,
}

/// What a name resolves to, sealed inside its record.
#[derive(Debug, BorshDeserialize)]
struct Profile {
    name: String,
    account: Option<[u8; 32]>,
    npk: Option<[u8; 32]>,
    vpk: Vec<u8>,
    _texts: Vec<(String, String)>,
}

/// Where a payment to a name goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameDestination {
    /// The name's private receiving keys: the chain sees neither recipient nor amount.
    Private { npk: [u8; 32], vpk: Vec<u8> },
    /// A public account the holder chose to publish.
    Public(AccountId),
}

impl NameDestination {
    pub fn into_identity(self) -> Result<AccountIdentity> {
        Ok(match self {
            Self::Private { npk, vpk } => AccountIdentity::PrivateForeign {
                npk: NullifierPublicKey(npk),
                vpk: ViewingPublicKey::from_bytes(vpk)
                    .map_err(|e| anyhow!("the name publishes an invalid viewing key: {e}"))?,
                kind: PrivateAccountKind::Regular,
            },
            Self::Public(account) => AccountIdentity::PublicNoSign(account),
        })
    }
}

/// `jef.lez` and `JEF` both mean the name `jef`.
#[must_use]
pub fn normalize(name: &str) -> String {
    let name = name.trim().to_lowercase();
    name.strip_suffix(SUFFIX).unwrap_or(&name).to_owned()
}

/// The name's public identifier and its secret key.
#[must_use]
pub fn derive(name: &str) -> ([u8; 32], [u8; 32]) {
    let params = Params::new(MASTER_MEMORY_KIB, MASTER_PASSES, MASTER_LANES, Some(32))
        .expect("the Argon2 parameters are valid");
    let mut master = [0_u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(name.as_bytes(), MASTER_SALT, &mut master)
        .expect("Argon2 accepts these inputs");
    (
        domain_hash(ID_DOMAIN, &master),
        domain_hash(KEY_DOMAIN, &master),
    )
}

/// The account holding the record of the name with identifier `id` in `registry`.
#[must_use]
pub fn record_address(registry: &AccountId, id: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(registry, &PdaSeed::new(domain_hash(RECORD_SEED_DOMAIN, id)))
}

/// Resolves `name` through `registry` to where a payment should go: the private keys
/// when the name has them, else its public account.
pub async fn resolve(
    wallet: &WalletCore,
    registry: AccountId,
    name: &str,
    now_ms: u64,
) -> Result<NameDestination> {
    let name = normalize(name);
    let (id, key) = derive(&name);
    let address = record_address(&registry, &id);
    let account = wallet
        .get_account_view(Actor::new(address, registry))
        .await
        .context("failed to read the name's record")?;
    let bytes = account
        .map(|account| account.data.actor_state(registry).to_vec())
        .unwrap_or_default();
    destination_from_record(&name, &key, &bytes, now_ms)
}

/// Decodes a record's bytes into where a payment to `name` goes.
pub fn destination_from_record(
    name: &str,
    key: &[u8; 32],
    record: &[u8],
    now_ms: u64,
) -> Result<NameDestination> {
    if record.is_empty() {
        bail!("{name}{SUFFIX} is not registered");
    }
    let record =
        NameRecord::try_from_slice(record).context("the registry holds a malformed record")?;
    // A name held by a deposit has `expires == u64::MAX` and never lapses.
    if record.expires != u64::MAX && now_ms >= record.expires.saturating_add(GRACE_MS) {
        bail!("{name}{SUFFIX} has expired");
    }
    let profile = open_profile(key, &record.sealed)
        .filter(|profile| profile.name == name)
        .ok_or_else(|| anyhow!("{name}{SUFFIX} has no readable record"))?;
    match (profile.npk, profile.vpk.is_empty(), profile.account) {
        (Some(npk), false, _) => Ok(NameDestination::Private {
            npk,
            vpk: profile.vpk,
        }),
        (_, _, Some(account)) => Ok(NameDestination::Public(AccountId::new(account))),
        _ => bail!("{name}{SUFFIX} has no payment destination"),
    }
}

fn open_profile(key: &[u8; 32], sealed: &[u8]) -> Option<Profile> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let plaintext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: RECORD_ASSOCIATED_DATA,
            },
        )
        .ok()?;
    // The profile is zero-padded; decode from the start and ignore the padding.
    Profile::deserialize(&mut plaintext.as_slice()).ok()
}

fn domain_hash(domain: &[u8], data: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(domain)
        .chain_update(data)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `jef`'s record on the LEZ v0.3.1 testnet registry
    /// `38jEfVV1RCyMzu1FGbYcCn5FqxCxKyY58VgzjruAh2gq` (registry v5), fetched 2026-10-16;
    /// held by a deposit, so `expires` is `u64::MAX`.
    const JEF_RECORD_HEX: &str = concat!(
        "051f7a805e586fde56a650481a62c11fd879b1831d43ecce56376a340c556ab992ffffffffffffffff1c0700",
        "00a024fe171e22a88540cab1e7e43c32d7d4b6ea212446bb237f1582b7f88139c30937a272d40a8a42de50ae",
        "507786beb9ece14459206f5f4b516008031ee92260f4a494f4c7af459ad50988f5757ec99b05fa45ebd56fea",
        "3d30c6d80d72d98113c250296d0d7e70d84b20eaf0bd8fd20ba8afc594768246119e85732a7b7fddd2dadc47",
        "5d09887e0f7fc5a42e039d7b3090b53fb57b79c2278f79243d40cee3d843717ad352f4609e7f3057fd570260",
        "5463054fd928bc818dd0d3fbf66e8512fe3efe6954e3b7fc361d685fabf14112f4a33d643b0124ca57c56ef6",
        "98ab00eb0b536e2dd1b42787870e0b6f33fec7a063c213233b408ad70381555defd01ad7d1b78bcdb616dfd4",
        "f734b55f35ebdfa483ddc6dd83cc200b2ed4e8dbf45adc98b1f15f4c31fecd36a46d0a82727b3c83411fe689",
        "0a5bb7cb2d9c8f3439a624bd930c7d338a728cc851dcefe1325ae4c5e4ac517e6a36df5932b360eb878b824f",
        "2b2a243aad79fbeaa74800b2566864ff31f24001805b8983cc99ea4d1d556a0efcaf4739bfafca575b9f38c6",
        "10df3007872ee0b5d66910ce5f50536090a49a098ed762ee7fbcd97c7f38f396bce5c82f930988f09dc1dc60",
        "322e69d2d960e42f9ab3763f2605c92c0dc34d1627ded81633e3bad2045d15db9d9d1c346887a3508c773a3a",
        "fe0dd4680b679d073fa2bdeab64d8f34bb85a78fbfe3558e3baacbafdf73e0584cd393b27218d1794af002c3",
        "5b43ee7e0a48cc09f31e0e9076933b16ec5bf5b02afc8511ccde19d3a2f90e2db4452639141828d0e348e33f",
        "fbdbef7eccd1377fd2c7552114565794dc66b1c53848e8d155b7e64edf99a428ce0c97451915608f96370ec5",
        "5f855dadaae1e4592ec66ad8b7abfdbfaf98bfbe068bbe93976f61a1ce233fba5485f6ca54710280cac810ba",
        "7106aba95adcace1e9c7c16a5569a720acae4fc13f8aca4ffb1e40bf3feeb2c98bfd54f437112664d41d3834",
        "a78a1d1cf9c185c5826a7a706be97ac1afcce4245a61fba380285ef1f4d1fbab9d9f1a5607e34f543481c214",
        "fefa5530c4e51cc7ae074ae11563ae74e6939bc648d1a0d0946a97bdcad8c7702cf8c534020e7edefea3c27b",
        "6a0f4628468ba57968c8ee9809afd1a00a737863eaa9dccbe0d85b02d8af8882df78b2cc100cd00d2402a1af",
        "fdab62cce7d57ad17a6832fb9c547fd5831f1585fb25ba15ae23c89e59fdc189c4cbed4d116a6dec1f2b6708",
        "a650b71d1e033840fe8f19b6542678150a2ac1987ed5c4f54f07797e3da192f4fcebe6a8d2fc8b2447698b2d",
        "fe067cff8162fa58e8b0d79f819ea419f5a1ee2cd79020c1a9436a3084c4681d9252560f5e186f36b3d48850",
        "57d58a60e4c8f360d2fbd7f2e27598f78c1e5abfbfb7b617521184c74996676209ce2c5e8451f887ed3caf68",
        "57ae27fddfd239d5713141ee4245807ee3249f60bcd9ee48ee44b12d2320d8fd6b54aefbc75e4957a5744726",
        "d8401e5028e3d9bb6b5bd70e4785fac6e1d7332f7892bd2265dbfbba336b7457eebd4fd6aa93c671dd5258bd",
        "ae89baa4fc65a7a7f83741f4866ba35944996919d46fa614408c9dd5338b3ad38204c7e2e97e3818a4ed9520",
        "3b7629cf6981ee8505983aa5c351f11e22cc358aa2cb8c8894d482b7f857f75adf295704bbdd1272acc1e775",
        "d47b0c321c1a20d007edc5bd6f5778db003d63f5df44c90f114af2b9515265781fa931fb34800c7bd0ce1b8f",
        "5d79b5a5c4daa3e4cb8bc80fc73598ed4bf7eb92074c933bc390e4aad3c879e1b17c6714b688ad5186d8e903",
        "140ce62355164489d75ff313e619f5523f49207934477d717a78effcc5ff008477a331a785ddf759643f4131",
        "fad408366c695c9e2e39448b89b92e36ab433931862731a0dc77cd48af0e0a1ad3828323e5f40bbe2ade3d05",
        "e9d60b5d9697868fe7f43f4c704d87247b05e96eb4a34cdeab40143b352becb0f78b365a6356a463d2243e60",
        "2389c0c0c50bbdc10f884861af74be4b5fa30d31ad44783125bb7afd1b0830faf8de98e073ade1a876267c76",
        "e679b59105baf75aa6bac7526ed5f4c7c9c042203a95ccf261d067da08bfe7523cb7cc3fbbe295764b80d033",
        "0939e4544f19a023a72132a58d8fc0fd1aa5f4f624a186275127c5a50462528b1d82c96790531cfebb2d4d1f",
        "909704090592854a95caf5d5bcdc95b0b76e0930e6e6973259a7ba84a5e061ad96c4ba2a74f650c345006000",
        "107212f1251ce40923fb867b91d42ead65c314177451449bb9f603fda7c34911c6f4f6a0bbb98e23202660c1",
        "c94f91ef3c1cadee1a1a5e0103470ae6ef27d911486968361341c188346bc9d965b46120016ded026a1d92cf",
        "f43cdc56b321c18f8e1b72f489244eab5d6c5ffe4d993403ef90253a011072dcf352396af90c3ae9eab24f3a",
        "2675dc0e7e00a3384159302ec02a1652c5a26bac4db760c08fa74151466e1839430366a4d90bc52310fdb529",
        "37b94e70a85f4b303eb8d5431eef629dfca480cc6987ae8eb20d16bf16f91210c9b0a620636d649eb14de820",
        "d23c75ba14b145a82196f53f878973ccaa",
    );
    const NOW: u64 = 1_792_160_000_000; // 2026-10-16

    fn jef_record() -> Vec<u8> {
        hex::decode(JEF_RECORD_HEX).unwrap()
    }

    #[test]
    fn derives_the_specification_vectors() {
        let (id, key) = derive("jef");
        assert_eq!(
            hex::encode(id),
            "7041d9e447f06bdfe327d870402b1524cfe38bd03445b8fc3d0e87bc978eb763"
        );
        assert_eq!(
            hex::encode(key),
            "aad91a1a3dd0fb56a213212fbea58fe25d9139db42fc59ce2116c3cfa3440088"
        );
    }

    #[test]
    fn normalizes_names() {
        assert_eq!(normalize(" JEF.lez "), "jef");
        assert_eq!(normalize("jef"), "jef");
    }

    #[test]
    fn finds_the_testnet_record_address() {
        let registry: AccountId = "38jEfVV1RCyMzu1FGbYcCn5FqxCxKyY58VgzjruAh2gq"
            .parse()
            .unwrap();
        let (id, _) = derive("jef");
        assert_eq!(
            record_address(&registry, &id).to_string(),
            "Cu8tskY2uaMA14EiMFJd8jGD5MreMw1XkvRheTJZvAk"
        );
    }

    #[test]
    fn resolves_a_real_record_to_private_keys() {
        let (_, key) = derive("jef");
        let NameDestination::Private { vpk, .. } =
            destination_from_record("jef", &key, &jef_record(), NOW).unwrap()
        else {
            panic!("jef publishes private receiving keys");
        };
        assert_eq!(vpk.len(), 1184);
    }

    #[test]
    fn refuses_the_wrong_name_an_empty_record_and_a_lapsed_name() {
        let (_, other_key) = derive("logos");
        assert!(destination_from_record("jef", &other_key, &jef_record(), NOW).is_err());
        let (_, key) = derive("jef");
        assert!(destination_from_record("jef", &key, &[], NOW).is_err());
    }

    #[test]
    fn a_deposit_held_name_never_lapses_but_a_term_name_does() {
        let (_, key) = derive("jef");
        // The recorded record is held by a deposit: expires is u64::MAX.
        assert!(destination_from_record("jef", &key, &jef_record(), u64::MAX - 1).is_ok());
        // The same record with a term expiry lapses after its grace.
        let mut term = jef_record();
        term[33..41].copy_from_slice(&1_000_u64.to_le_bytes());
        assert!(destination_from_record("jef", &key, &term, 1_000 + GRACE_MS - 1).is_ok());
        assert!(destination_from_record("jef", &key, &term, 1_000 + GRACE_MS).is_err());
    }
}
