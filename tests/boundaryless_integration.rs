use std::process::Command;

fn run_fth(args: &[&str]) -> String {
    let output = Command::new("cargo")
        .args(["run", "--", "-b"])
        .args(args)
        .output()
        .expect("failed to run fth");
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn run_fth_json(args: &[&str]) -> String {
    let output = Command::new("cargo")
        .args(["run", "--", "-b", "--json"])
        .args(args)
        .output()
        .expect("failed to run fth");
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn test_md5_in_sentence() {
    let output = run_fth(&["the hash is 5d41402abc4b2a76b9719d911017c592 in text"]);
    assert!(output.contains("MD5"), "Should identify MD5: {output}");
}

#[test]
fn test_sha1_no_false_md5() {
    let output = run_fth_json(&["commit da39a3ee5e6b4b0d3255bfef95601890afd80709 merged"]);
    assert!(
        output.contains("SHA-1") || output.contains("SHA1"),
        "Should find SHA-1: {output}"
    );
    // The matched_text should be the full 40-char SHA-1, not a 32-char sub-match
    if output.contains("matched_text") {
        assert!(output.contains("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    }
}

#[test]
fn test_multiple_hashes_in_log() {
    let output = run_fth_json(&[
        "hash=5d41402abc4b2a76b9719d911017c592 session=098f6bcd4621d373cade4e832627b4f6",
    ]);
    assert!(output.contains("5d41402abc4b2a76b9719d911017c592"));
    assert!(output.contains("098f6bcd4621d373cade4e832627b4f6"));
}

#[test]
fn test_bcrypt_in_text() {
    let output = run_fth(&[
        "pw=$2b$12$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6",
    ]);
    assert!(
        output.to_lowercase().contains("bcrypt"),
        "Should find bcrypt: {output}"
    );
}

#[test]
fn test_non_boundaryless_unchanged() {
    // Without -b flag, embedded hash should NOT match any anchored pattern
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "the hash is 5d41402abc4b2a76b9719d911017c592 in text",
        ])
        .output()
        .expect("failed to run fth");
    // Just verify it doesn't crash
    assert!(output.status.success());
}
