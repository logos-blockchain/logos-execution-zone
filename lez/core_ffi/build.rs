use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    let config =
        cbindgen::Config::from_file(std::path::Path::new(&crate_dir).join("cbindgen.toml"))
            .expect("failed to load cbindgen.toml");

    cbindgen::Builder::new()
        .with_config(config) // must come first
        .with_crate(&crate_dir)
        .with_language(cbindgen::Language::C)
        .with_cpp_compat(true)
        .with_pragma_once(true)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("core_ffi.h");
}
