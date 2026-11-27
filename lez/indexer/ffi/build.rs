#[path = "../../ffi_types/endpoint_header.rs"]
mod endpoint_header;

fn main() {
    endpoint_header::write("indexer_ffi.h");
}
