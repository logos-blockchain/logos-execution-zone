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
pub const fn scripted() -> Program {
    use guests::{SCRIPTED_ELF, SCRIPTED_ID, SCRIPTED_PATH};

    let _unused = SCRIPTED_PATH;

    Program::new_unchecked(SCRIPTED_ID, Cow::Borrowed(SCRIPTED_ELF))
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
pub const fn cooldown() -> Program {
    use guests::{COOLDOWN_ELF, COOLDOWN_ID, COOLDOWN_PATH};

    let _unused = COOLDOWN_PATH;

    Program::new_unchecked(COOLDOWN_ID, Cow::Borrowed(COOLDOWN_ELF))
}

#[must_use]
#[inline]
pub const fn clock_reader() -> Program {
    use guests::{CLOCK_READER_ELF, CLOCK_READER_ID, CLOCK_READER_PATH};

    let _unused = CLOCK_READER_PATH;

    Program::new_unchecked(CLOCK_READER_ID, Cow::Borrowed(CLOCK_READER_ELF))
}

#[must_use]
#[inline]
pub const fn listener() -> Program {
    use guests::{LISTENER_ELF, LISTENER_ID, LISTENER_PATH};

    let _unused = LISTENER_PATH;

    Program::new_unchecked(LISTENER_ID, Cow::Borrowed(LISTENER_ELF))
}

#[must_use]
#[inline]
pub const fn live_payout() -> Program {
    use guests::{LIVE_PAYOUT_ELF, LIVE_PAYOUT_ID, LIVE_PAYOUT_PATH};

    let _unused = LIVE_PAYOUT_PATH;

    Program::new_unchecked(LIVE_PAYOUT_ID, Cow::Borrowed(LIVE_PAYOUT_ELF))
}

#[must_use]
#[inline]
pub const fn zone_chat() -> Program {
    use guests::{ZONE_CHAT_ELF, ZONE_CHAT_ID, ZONE_CHAT_PATH};

    let _unused = ZONE_CHAT_PATH;

    Program::new_unchecked(ZONE_CHAT_ID, Cow::Borrowed(ZONE_CHAT_ELF))
}
