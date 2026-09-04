use std::ffi::{CString, c_char};

/// # Safety
/// It's up to the caller to pass a proper pointer, if somehow from c/c++ side
/// this is called with a type which doesn't come from a returned `CString` it
/// will cause a segfault.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_cstring(block: *mut c_char) {
    if block.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    drop(unsafe { CString::from_raw(block) });
}
