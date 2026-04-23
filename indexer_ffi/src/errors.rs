#[derive(Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub enum OperationStatus {
    #[default]
    Ok = 0x0,
    NullPointer = 0x1,
    InitializationError = 0x2,
    ClientError = 0x3,
}

impl OperationStatus {
    #[must_use]
    #[unsafe(no_mangle)]
    pub extern "C" fn is_ok(&self) -> bool {
        *self == Self::Ok
    }

    #[must_use]
    #[unsafe(no_mangle)]
    pub extern "C" fn is_error(&self) -> bool {
        !self.is_ok()
    }
}
