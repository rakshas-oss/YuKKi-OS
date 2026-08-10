fn main() {
   println!("cargo:rerun-if-changed=src/ffi/chaos_weave.c");
   cc::Build::new().file("src/ffi/chaos_weave.c").include("src/ffi").flag("-std=c99").compile("chaos_weave");
}
