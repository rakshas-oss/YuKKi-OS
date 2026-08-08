fn main() {
    println!("cargo:rerun-if-changed=src/ffi/chaos_weave.c");
    println!("cargo:rerun-if-changed=src/ffi/laminar_api.h");

    let mut build = cc::Build::new();
    build.file("src/ffi/chaos_weave.c");
    build.include("src/ffi");
    build.flag_if_supported("-std=c99");
    build.flag_if_supported("/std:c11");
    build.compile("chaos_weave");
}
