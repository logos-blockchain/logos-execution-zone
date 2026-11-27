#[derive(Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub enum OperationStatus {
    #[default]
    Ok = 0x0,
    NullPointer = 0x1,
    InitializationError = 0x2,
    ClientError = 0x3,
    InvalidArgument = 0x4,
}

impl OperationStatus {
    #[must_use]
    pub fn is_ok(&self) -> bool {
        *self == Self::Ok
    }

    #[must_use]
    pub fn is_error(&self) -> bool {
        !self.is_ok()
    }
}
