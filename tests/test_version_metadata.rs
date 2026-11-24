use std::{fs, path::Path};

#[test]
fn package_version_matches_release_metadata() {
    let package_version = env!("CARGO_PKG_VERSION");
    let expected_lock_entry = format!(
        "name = \"yukkios\"\nversion = \"{package_version}\""
    );
    let lockfile = fs::read_to_string("Cargo.lock").expect("read Cargo.lock");
    assert!(
        lockfile.contains(&expected_lock_entry),
        "Cargo.lock package entry for yukkios must match Cargo.toml version {package_version}"
    );

    let dockerfile = fs::read_to_string("Dockerfile").expect("read Dockerfile");
    let expected_oci_label = format!(
        "org.opencontainers.image.version=\"{package_version}\""
    );
    assert!(
        dockerfile.contains(&expected_oci_label),
        "Docker image version label must match Cargo.toml version {package_version}"
    );

    let readme = fs::read_to_string("README.md").expect("read README.md");
    let expected_heading = format!("# YuKKi-OS v{package_version}");
    assert!(
        readme.starts_with(&expected_heading),
        "README heading must identify release candidate {package_version}"
    );
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
