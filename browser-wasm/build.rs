fn main() {
    if let Ok(arch) = std::env::var("CARGO_CFG_TARGET_ARCH") {
        if arch == "wasm32" {
            // The browser shell writes frame bytes into the exported linear
            // memory before calling the bounded Rust validation entry point.
            println!("cargo:rustc-link-arg=--export-memory");
        }
    }
}
