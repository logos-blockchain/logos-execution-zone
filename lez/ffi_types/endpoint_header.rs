use std::{env, path::Path};

pub fn write(header: &str) {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let shared_dir = Path::new(&crate_dir).join("../../ffi_types");
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=../../ffi_types/src/");
    println!("cargo:rerun-if-changed=../../ffi_types/cbindgen.toml");
    let shared_config = cbindgen::Config::from_file(shared_dir.join("cbindgen.toml"))
        .expect("Unable to read the shared cbindgen.toml");
    let mut shared_header = Vec::new();
    cbindgen::Builder::new()
        .with_crate(&shared_dir)
        .with_config(shared_config)
        .generate()
        .expect("Unable to generate the shared bindings")
        .write(&mut shared_header);
    let shared_header = String::from_utf8(shared_header).expect("bindings are UTF-8");
    let mut builder = cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .with_cpp_compat(true)
        .with_pragma_once(true)
        .with_parse_deps(true)
        .with_parse_include(&["ffi_types"])
        .with_include("ffi_types.h");
    for name in shared_header.lines().filter_map(defined_name) {
        builder = builder.exclude_item(name);
    }
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(header);
}

fn defined_name(line: &str) -> Option<&str> {
    let declaration = line
        .strip_prefix("} ")
        .or_else(|| line.strip_prefix("typedef "))?;
    declaration.strip_suffix(';')?.rsplit(' ').next()
}
