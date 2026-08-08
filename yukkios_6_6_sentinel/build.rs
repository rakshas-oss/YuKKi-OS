fn main() {
    cc::Build::new()
        .file("src/ffi/chaos_weave.c")
        .include("src/ffi")
        .flag("-std=c99")
        .flag("-O2")
        .compile("chaos_weave");

    println!("cargo:rerun-if-changed=src/ffi/chaos_weave.c");
    println!("cargo:rerun-if-changed=src/ffi/laminar_api.h");
}
