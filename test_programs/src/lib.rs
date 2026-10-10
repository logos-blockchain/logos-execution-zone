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
