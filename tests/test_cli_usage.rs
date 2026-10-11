use std::process::Command;

#[test]
fn cli_prints_usage_for_invalid_arguments() {
    let bin = env!("CARGO_BIN_EXE_yukki_core_node");
    let output = Command::new(bin)
        .env(
            "YUKKI_PSK_HEX",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .output()
        .expect("run binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage: yukki_core_node bootstrap <bind-address> | node <bootstrap-address> <advertised-address>"));
}

#[test]
fn gateway_requires_a_token_unless_insecure_development_is_explicit() {
    let bin = env!("CARGO_BIN_EXE_yukki_core_node");
    let output = Command::new(bin)
        .args(["gateway", "127.0.0.1:0"])
        .env_remove("YUKKI_GATEWAY_TOKEN")
        .output()
        .expect("run gateway");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("YUKKI_GATEWAY_TOKEN is required"));
}
