use common::{HashType, transaction::NSSATransaction};
use nssa::{
    AccountId, PublicTransaction,
    program::Program,
    public_transaction::{Message, WitnessSet},
};
use pyo3::Python;
use sequencer_service_rpc::RpcClient as _;

use super::NativeTokenTransfer;
use crate::{
    ExecutionFailureKind, WalletCore,
    cli::{keycard_wallet::KeycardWallet, python_path},
};

impl NativeTokenTransfer<'_> {
    pub async fn send_public_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        balance_to_move: u128,
        pin: &Option<String>,
        key_path: &Option<String>,
    ) -> Result<HashType, ExecutionFailureKind> {
        let balance = self
            .0
            .get_account_balance(from)
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        if balance >= balance_to_move {
            let account_ids = vec![from, to];
            let program_id = Program::authenticated_transfer_program().id();

            let mut sign_ids = Vec::new();
            sign_ids.push(from);

            let mut nonces = self
                .0
                .get_accounts_nonces(vec![from])
                .await
                .map_err(ExecutionFailureKind::SequencerError)?;
            let to_signing_key = self.0.storage.user_data.get_pub_account_signing_key(to);
            if let Some(_to_signing_key) = to_signing_key {
                sign_ids.push(to);
                let to_nonces = self
                    .0
                    .get_accounts_nonces(vec![to])
                    .await
                    .map_err(ExecutionFailureKind::SequencerError)?;
                nonces.extend(to_nonces);
            } else {
                println!(
                    "Receiver's account ({to}) private key not found in wallet. Proceeding with only sender's key."
                );
            }

            let message =
                Message::try_new(program_id, account_ids, nonces, balance_to_move).unwrap();

            let witness_set = if pin.is_none() {
                    WalletCore::sign_public_message(self.0, &message, &sign_ids)
                                    .expect("Expect a valid signature")
                } else {
                                    // TODO: maybe the issue? (Marvin)
                    let message_bytes: [u8; 32] = {
                        let v = message.to_bytes();
                        let mut bytes = [0_u8; 32];
                        let len = v.len().min(32);
                        bytes[..len].copy_from_slice(&v[..len]);
                        bytes
                    };
                    let pub_key = KeycardWallet::get_public_key_for_path_with_connect(&pin.as_ref().expect("TODO"), &key_path.as_ref().expect("TODO"));
                    let signature = KeycardWallet::sign_message_for_path_with_connection(&pin.as_ref().expect("TODO"), &key_path.as_ref().expect("TODO"), &message_bytes).expect("Expect valid signature");
                    WitnessSet::from_list(&[signature], &[pub_key])
                };

            let tx = PublicTransaction::new(message, witness_set);

            Ok(self
                .0
                .sequencer_client
                .send_transaction(NSSATransaction::Public(tx))
                .await?)
        } else {
            Err(ExecutionFailureKind::InsufficientFundsError)
        }
    }

    pub async fn register_account(
        &self,
        from: AccountId,
        pin: &Option<String>,      // Used by Keycard.
        key_path: &Option<String>, // Used by Keycard.
    ) -> Result<HashType, ExecutionFailureKind> {
        let nonces = self
            .0
            .get_accounts_nonces(vec![from])
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        let instruction: u128 = 0;
        let account_ids = vec![from];
        let program_id = Program::authenticated_transfer_program().id();
        let message = Message::try_new(program_id, account_ids, nonces, instruction).unwrap();

        // (Marvin): This really needs to be the ChainIndex
        // But, I cannot change that due to Default Accounts.
        // Instead, I had introduced a "NEW" sign...which I do not see...
        // Correction: I did not need a specific function. Rather, I use `from_list` to combine
        // public and signatures together for a WitnessSet.

        // The tricky part is that I NEED to do everything with chain-codes... This won't look nice,
        // but is feasible.
        let witness_set = if pin.is_none() {
            let signing_key = self.0.storage.user_data.get_pub_account_signing_key(from);

            let Some(signing_key) = signing_key else {
                return Err(ExecutionFailureKind::KeyNotFoundError);
            };

            WitnessSet::for_message(&message, &[signing_key])
        } else {
            let witness_set = Python::with_gil(|py| {
                python_path::add_python_path(py).expect("keycard_wallet.py not found");

                let wallet = KeycardWallet::new(py).expect("Expect keycard wallet");

                let is_connected = wallet
                    .setup_communication(py, pin.as_ref().expect("TODO"))
                    .expect("Expect a Boolean.");

                if is_connected {
                    println!("\u{2705} Keycard is now connected to wallet.");
                } else {
                    println!("\u{274c} Keycard is not connected to wallet.");
                }
                // TODO: maybe the issue? (Marvin)
                let message: [u8; 32] = {
                    let v = message.to_bytes();
                    let mut bytes = [0_u8; 32];
                    let len = v.len().min(32);
                    bytes[..len].copy_from_slice(&v[..len]);
                    bytes
                };

                let pub_key = wallet
                    .get_public_key_for_path(py, key_path.as_ref().expect("TODO"))
                    .expect("Expect a valid public key");

                let signature = wallet
                    .sign_message_for_path(py, key_path.as_ref().expect("TODO"), &message)
                    .expect("TODO");

                let _ = wallet.disconnect(py);

                WitnessSet::from_list(&[signature], &[pub_key])
            });
            witness_set
        };

        let tx = PublicTransaction::new(message, witness_set);

        Ok(self
            .0
            .sequencer_client
            .send_transaction(NSSATransaction::Public(tx))
            .await?)
    }
}
