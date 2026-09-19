use std::{fs, path::Path};

#[test]
fn package_version_is_v6_7_0() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "6.7.0");
}

#[test]
fn cargo_manifest_has_expected_binary_name() {
    let manifest = fs::read_to_string("Cargo.toml").expect("read Cargo.toml");
    assert!(manifest.contains("name = \"yukki_core_node\""));
}

#[test]
fn v6_7_deploy_script_exists_and_legacy_script_removed() {
    assert!(Path::new("scripts/deploy/deploy_yukki_6_7_0_inet3.zsh").exists());
    assert!(!Path::new("scripts/deploy/deploy_yukki_6_6_6_inet3.zsh").exists());
}
