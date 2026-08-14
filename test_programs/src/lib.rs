#![expect(
    clippy::no_effect_underscore_binding,
    reason = "This way we can remove warnings about unused path constants"
)]

use std::borrow::Cow;

use lee::program::Program;

mod guests {
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));
}

#[must_use]
#[inline]
pub const fn simple_balance_transfer() -> Program {
    use guests::{
        SIMPLE_BALANCE_TRANSFER_ELF, SIMPLE_BALANCE_TRANSFER_ID, SIMPLE_BALANCE_TRANSFER_PATH,
    };

    let _unused = SIMPLE_BALANCE_TRANSFER_PATH;

    Program::new_unchecked(
        SIMPLE_BALANCE_TRANSFER_ID,
        Cow::Borrowed(SIMPLE_BALANCE_TRANSFER_ELF),
    )
}

#[must_use]
#[inline]
pub const fn chain_caller() -> Program {
    use guests::{CHAIN_CALLER_ELF, CHAIN_CALLER_ID, CHAIN_CALLER_PATH};

    let _unused = CHAIN_CALLER_PATH;

    Program::new_unchecked(CHAIN_CALLER_ID, Cow::Borrowed(CHAIN_CALLER_ELF))
}

#[must_use]
#[inline]
pub const fn claimer() -> Program {
    use guests::{CLAIMER_ELF, CLAIMER_ID, CLAIMER_PATH};

    let _unused = CLAIMER_PATH;

    Program::new_unchecked(CLAIMER_ID, Cow::Borrowed(CLAIMER_ELF))
}

#[must_use]
#[inline]
pub const fn pda_spend_proxy() -> Program {
    use guests::{PDA_SPEND_PROXY_ELF, PDA_SPEND_PROXY_ID, PDA_SPEND_PROXY_PATH};

    let _unused = PDA_SPEND_PROXY_PATH;

    Program::new_unchecked(PDA_SPEND_PROXY_ID, Cow::Borrowed(PDA_SPEND_PROXY_ELF))
}

#[must_use]
#[inline]
pub const fn time_locked_transfer() -> Program {
    use guests::{TIME_LOCKED_TRANSFER_ELF, TIME_LOCKED_TRANSFER_ID, TIME_LOCKED_TRANSFER_PATH};

    let _unused = TIME_LOCKED_TRANSFER_PATH;

    Program::new_unchecked(
        TIME_LOCKED_TRANSFER_ID,
        Cow::Borrowed(TIME_LOCKED_TRANSFER_ELF),
    )
}

#[must_use]
#[inline]
pub const fn pinata_cooldown() -> Program {
    use guests::{PINATA_COOLDOWN_ELF, PINATA_COOLDOWN_ID, PINATA_COOLDOWN_PATH};

    let _unused = PINATA_COOLDOWN_PATH;

    Program::new_unchecked(PINATA_COOLDOWN_ID, Cow::Borrowed(PINATA_COOLDOWN_ELF))
}

#[must_use]
#[inline]
pub const fn faucet_chain_caller() -> Program {
    use guests::{FAUCET_CHAIN_CALLER_ELF, FAUCET_CHAIN_CALLER_ID, FAUCET_CHAIN_CALLER_PATH};

    let _unused = FAUCET_CHAIN_CALLER_PATH;

    Program::new_unchecked(
        FAUCET_CHAIN_CALLER_ID,
        Cow::Borrowed(FAUCET_CHAIN_CALLER_ELF),
    )
}

#[must_use]
#[inline]
pub const fn clock_chain_caller() -> Program {
    use guests::{CLOCK_CHAIN_CALLER_ELF, CLOCK_CHAIN_CALLER_ID, CLOCK_CHAIN_CALLER_PATH};

    let _unused = CLOCK_CHAIN_CALLER_PATH;

    Program::new_unchecked(CLOCK_CHAIN_CALLER_ID, Cow::Borrowed(CLOCK_CHAIN_CALLER_ELF))
}
