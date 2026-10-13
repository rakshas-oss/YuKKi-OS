fn main() {
    // Watch the new C sources and headers so Cargo rebuilds when they change
    println!("cargo:rerun-if-changed=src/ffi/chaos_weave.c");
    println!("cargo:rerun-if-changed=kernel/yukki_mesh.c");
    println!("cargo:rerun-if-changed=kernel/yukki_emcon.c");
    println!("cargo:rerun-if-changed=kernel/yukki_fhss.c");
    println!("cargo:rerun-if-changed=kernel/yukki_crypto.c");
    println!("cargo:rerun-if-changed=include/yukki_mesh.h");
    println!("cargo:rerun-if-changed=include/yukki_emcon.h");
    println!("cargo:rerun-if-changed=include/yukki_fhss.h");
    println!("cargo:rerun-if-changed=include/yukki_crypto.h");

    let mut builder = cc::Build::new();
    builder
        .file("src/ffi/chaos_weave.c")
        .file("kernel/yukki_mesh.c")
        .file("kernel/yukki_emcon.c")
        .file("kernel/yukki_fhss.c")
        .file("kernel/yukki_crypto.c")
        .include("src/ffi")
        .include("include")
        .flag("-std=c99");

    // Optional native crypto feature will define USE_MBEDTLS and request linking
    if std::env::var("CARGO_FEATURE_NATIVE_CRYPTO").is_ok() {
        builder.define("USE_MBEDTLS", None);
        // Link mbed TLS libs when the feature is enabled. Ensure system packages are available.
        println!("cargo:rustc-link-lib=mbedcrypto");
        println!("cargo:rustc-link-lib=mbedtls");
        println!("cargo:rustc-link-lib=mbedx509");
    }

    builder.compile("yukki_native");
}
