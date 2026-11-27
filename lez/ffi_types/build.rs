fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    let config =
        cbindgen::Config::from_file("cbindgen.toml").expect("Unable to read cbindgen.toml");
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("ffi_types.h");
}
