//! Runs ../test.sh against the binary this build produced, so `cargo test` and
//! `cargo mutants` check the CLI's behaviour, not only the unit tests.
use std::process::Command;

#[test]
fn test_sh_passes() {
    let status = Command::new("bash")
        .arg("test.sh")
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
        .env("INTEGRITY_IMPLS", env!("CARGO_BIN_EXE_integrity-check"))
        .status()
        .expect("bash runs");
    assert!(status.success(), "test.sh failed");
}
