pub mod routing;
pub mod macros;

pub mod prelude {
    // Re-export tipe routing & context
    pub use crate::routing::{ExecCtx, ReturnRoute, GeneralCallInstruction};
    
    // Re-export declarative macros (CPS Engine)
    pub use crate::{call_program, return_to_caller, lez_dispatcher};
    
    // Re-export procedural macros (#[public], #[internal]) 
    pub use lez_sdk_macros::{public, internal};

    pub use risc0_zkvm;
    pub use sha2;
    pub use bytemuck;
}