#![expect(
    clippy::print_stdout,
    reason = "This is a CLI test helper, printing to stdout is expected and convenient"
)]

//! Forces the card in the first available reader into the unpowered state via PC/SC
//! `SCARD_UNPOWER_CARD`. Run immediately before a wallet command to simulate the power-loss
//! condition reported on some USB reader/driver combinations.
//!
//! Either:
//! - pcscd re-powers the card on the next `SCardConnect`, so wallet commands will succeed without
//!   triggering the retry path.
//! - the card stays unpowered, triggering a PC/SC transport error (`keycard_rs::Error::Io`) and
//!   exercising the reconnect-and-retry wrapper in `KeycardWallet::connect()`.

fn main() {
    let context = match pcsc::Context::establish(pcsc::Scope::User) {
        Ok(context) => context,
        Err(e) => {
            println!("force_unpower: failed to establish PC/SC context ({e}), skipping.");
            return;
        }
    };

    let readers = match context.list_readers_owned() {
        Ok(readers) => readers,
        Err(e) => {
            println!("force_unpower: failed to list readers ({e}), skipping.");
            return;
        }
    };

    let Some(reader) = readers.first() else {
        println!("force_unpower: no readers found, skipping.");
        return;
    };

    let card = match context.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY) {
        Ok(card) => card,
        Err(e) => {
            println!("force_unpower: connect failed ({e}), skipping.");
            return;
        }
    };

    if let Err((_card, e)) = card.disconnect(pcsc::Disposition::UnpowerCard) {
        println!("force_unpower: disconnect failed ({e}), skipping.");
        return;
    }

    println!("force_unpower: card powered down.");
}
