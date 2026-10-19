#[derive(Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub enum PrimitiveOperationStatus {
    #[default]
    Ok = 0x0,
    CastError = 0x1,
}

impl PrimitiveOperationStatus {
    #[must_use]
    pub fn is_ok(&self) -> bool {
        *self == Self::Ok
    }

    #[must_use]
    pub fn is_error(&self) -> bool {
        !self.is_ok()
    }
}
