use std::{fs, path::Path};

#[test]
fn package_version_is_v6_9_0() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "6.9.0");
}

#[test]
fn cargo_manifest_has_expected_binary_name() {
    let manifest = fs::read_to_string("Cargo.toml").expect("read Cargo.toml");
    assert!(manifest.contains("name = \"yukki_core_node\""));
}

#[test]
fn v6_8_deploy_script_exists_and_legacy_script_removed() {
    assert!(Path::new("scripts/deploy/deploy_yukki_6_8_0_inet3.zsh").exists());
    assert!(!Path::new("scripts/deploy/deploy_yukki_6_6_6_inet3.zsh").exists());
}
