fn main() {
    println!("cargo:rerun-if-changed=src/ffi/chaos_weave.c");
    println!("cargo:rerun-if-changed=src/ffi/crypt_layer.c");
    println!("cargo:rerun-if-changed=src/ffi/laminar_api.h");
    cc::Build::new()
        .file("src/ffi/chaos_weave.c")
        .file("src/ffi/crypt_layer.c")
        .include("src/ffi")
        .flag("-std=c99")
        .compile("chaos_weave");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=pthread");
}
