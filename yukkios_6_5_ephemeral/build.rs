fn main() {
    println!("cargo:rerun-if-changed=src/ffi/chaos_weave.c");
    println!("cargo:rerun-if-changed=src/ffi/laminar_api.h");

    let mut build = cc::Build::new();
    build.file("src/ffi/chaos_weave.c");
    build.include("src/ffi");
    build.flag_if_supported("-std=c99");
    build.flag_if_supported("/std:c11");
    // Link libm for math functions (sqrt, exp) on Linux/macOS
    println!("cargo:rustc-link-lib=m");
    build.compile("chaos_weave");
}
