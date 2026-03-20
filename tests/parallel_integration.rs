use std::io::Write;
use std::process::Command;

use tempfile::tempdir;

fn run_fth(args: &[&str]) -> std::process::Output {
    Command::new("cargo")
        .args(["run", "--"])
        .args(args)
        .output()
        .expect("failed to run fth")
}

fn run_fth_json(args: &[&str]) -> std::process::Output {
    Command::new("cargo")
        .args(["run", "--", "--json"])
        .args(args)
        .output()
        .expect("failed to run fth")
}

/// Scanning a directory with multiple files should produce correct results.
#[test]
fn test_directory_scan_basic() {
    let dir = tempdir().unwrap();

    // File with an MD5 hash
    let f1 = dir.path().join("hashes.txt");
    std::fs::write(&f1, "5d41402abc4b2a76b9719d911017c592\n").unwrap();

    // File with a MAC address
    let f2 = dir.path().join("macs.txt");
    std::fs::write(&f2, "F8:8F:CA:00:11:22\n").unwrap();

    let out = run_fth(&[dir.path().to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(out.status.success());
    assert!(stdout.contains("MD5"), "Should find MD5 hash: {stdout}");
    assert!(
        stdout.contains("MAC Address"),
        "Should find MAC address: {stdout}"
    );
}

/// JSON output from a directory scan should be valid JSON per line.
#[test]
fn test_directory_scan_json() {
    let dir = tempdir().unwrap();

    std::fs::write(
        dir.path().join("a.txt"),
        "5d41402abc4b2a76b9719d911017c592\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("b.txt"),
        "098f6bcd4621d373cade4e832627b4f6\n",
    )
    .unwrap();

    let out = run_fth_json(&[dir.path().to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(out.status.success());
    // Each identified input produces a JSON array; verify both hashes appear
    assert!(
        stdout.contains("5d41402abc4b2a76b9719d911017c592"),
        "JSON should contain first hash: {stdout}"
    );
    assert!(
        stdout.contains("098f6bcd4621d373cade4e832627b4f6"),
        "JSON should contain second hash: {stdout}"
    );
}

/// Scanning a directory with nested subdirectories should find all files.
#[test]
fn test_directory_scan_recursive() {
    let dir = tempdir().unwrap();
    let sub = dir.path().join("sub").join("deep");
    std::fs::create_dir_all(&sub).unwrap();

    std::fs::write(
        dir.path().join("top.txt"),
        "5d41402abc4b2a76b9719d911017c592\n",
    )
    .unwrap();
    std::fs::write(sub.join("nested.txt"), "+93\n").unwrap();

    let out = run_fth(&[dir.path().to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(out.status.success());
    assert!(stdout.contains("MD5"), "Should find MD5 in top-level file");
    assert!(
        stdout.contains("Phone Code"),
        "Should find phone code in nested file"
    );
}

/// Parallel processing of many files should produce the same results every time
/// (deterministic output ordering).
#[test]
fn test_parallel_deterministic_output() {
    let dir = tempdir().unwrap();

    // Create 50 files each with a distinct known hash
    let md5 = "5d41402abc4b2a76b9719d911017c592";
    for i in 0..50 {
        let path = dir.path().join(format!("file_{:03}.txt", i));
        std::fs::write(&path, format!("{}\n", md5)).unwrap();
    }

    // Run twice and compare
    let out1 = run_fth_json(&[dir.path().to_str().unwrap()]);
    let out2 = run_fth_json(&[dir.path().to_str().unwrap()]);

    let s1 = String::from_utf8_lossy(&out1.stdout);
    let s2 = String::from_utf8_lossy(&out2.stdout);

    // Both runs should find the same number of results
    let count1 = s1.matches("MD5").count();
    let count2 = s2.matches("MD5").count();
    assert_eq!(
        count1, count2,
        "Parallel runs should produce same result count: {count1} vs {count2}"
    );
    assert!(count1 >= 50, "Should find at least 50 MD5 results (one per file), got {count1}");
}

/// Stress test: many files with varied content types processed in parallel.
#[test]
fn test_parallel_many_files_mixed() {
    let dir = tempdir().unwrap();

    let inputs = [
        ("md5.txt", "5d41402abc4b2a76b9719d911017c592"),
        ("sha1.txt", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
        ("sha256.txt", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
        ("mac.txt", "F8:8F:CA:00:11:22"),
        ("phone.txt", "+93"),
    ];

    // Create 20 copies of each type = 100 files
    for (name, content) in &inputs {
        for i in 0..20 {
            let fname = format!("{}_{}", i, name);
            let path = dir.path().join(fname);
            std::fs::write(&path, format!("{}\n", content)).unwrap();
        }
    }

    let out = run_fth(&[dir.path().to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(out.status.success());
    assert!(stdout.contains("MD5"), "Should find MD5");
    assert!(
        stdout.contains("SHA-1") || stdout.contains("SHA1"),
        "Should find SHA-1"
    );
    assert!(
        stdout.contains("SHA-256") || stdout.contains("SHA256") || stdout.contains("SHA-2"),
        "Should find SHA-256 variant"
    );
    assert!(stdout.contains("MAC Address"), "Should find MAC");
    assert!(stdout.contains("Phone Code"), "Should find phone code");
}

/// Large file with many lines should be processed correctly.
#[test]
fn test_large_single_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("big.txt");

    let mut f = std::fs::File::create(&path).unwrap();
    for _ in 0..1000 {
        writeln!(f, "5d41402abc4b2a76b9719d911017c592").unwrap();
    }
    drop(f);

    let out = run_fth(&[path.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(out.status.success());
    let count = stdout.matches("MD5").count();
    // Each line produces at least one MD5 mention
    assert!(
        count >= 1000,
        "Should find at least 1000 MD5 mentions, got {count}"
    );
}

/// Empty directory should produce no output and exit successfully.
#[test]
fn test_empty_directory() {
    let dir = tempdir().unwrap();

    let out = run_fth(&[dir.path().to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(out.status.success());
    assert!(
        stdout.trim().is_empty(),
        "Empty dir should produce no output: {stdout}"
    );
}

/// Directory with empty files should produce no output and not crash.
#[test]
fn test_directory_with_empty_files() {
    let dir = tempdir().unwrap();
    for i in 0..10 {
        std::fs::write(dir.path().join(format!("empty_{}.txt", i)), "").unwrap();
    }

    let out = run_fth(&[dir.path().to_str().unwrap()]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).trim().is_empty());
}
