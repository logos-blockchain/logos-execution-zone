//! Regenerates the recovery bindings the testnet genesis pins for its private accounts, under
//! fresh encapsulation randomness. Run it, with `--features regenerate`, when the accounts or the
//! note format change, then commit `src/genesis_recovery_bindings.bin`.

use lee::RecipientEncryption;
use lee_core::EphemeralSecretKey;

fn main() -> std::io::Result<()> {
    let bindings: Vec<_> = testnet_initial_state::initial_priv_accounts_private_keys()
        .iter()
        .map(|data| {
            RecipientEncryption {
                recipient: data.recipient(),
                esk: EphemeralSecretKey(rand::random()),
            }
            .bind_recovery()
        })
        .collect();
    std::fs::write(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/genesis_recovery_bindings.bin"
        ),
        borsh::to_vec(&bindings)?,
    )
}
