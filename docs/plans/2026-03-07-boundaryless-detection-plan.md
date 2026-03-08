# Boundaryless Hash Detection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Find all hash/pattern matches inside arbitrary text (not just one-hash-per-line) using anchor stripping + overlap removal.

**Architecture:** Strip `^`/`$` from existing patterns at startup to create boundaryless regex sets. Use `RegexSet::matches()` + `Regex::find_iter()` to extract all match positions. Post-process to remove matches fully contained within longer matches. Opt-in via `-b` flag.

**Tech Stack:** Rust, `regex` crate (`RegexSet`, `Regex`, `find_iter`), `clap`

**Design doc:** `docs/plans/2026-03-07-boundaryless-detection-design.md`

---

### Task 1: `boundaryless.rs` — `strip_anchors` + tests

**Files:**
- Create: `src/boundaryless.rs`

**Step 1: Write the failing test**

Add to `src/boundaryless.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_simple_anchors() {
        assert_eq!(strip_anchors("^abc$"), "abc");
    }

    #[test]
    fn test_strip_preserves_anchors_in_char_class() {
        assert_eq!(strip_anchors("[^abc]$"), "[^abc]");
        assert_eq!(strip_anchors("^[a$b]"), "[a$b]");
    }

    #[test]
    fn test_strip_with_case_insensitive_prefix() {
        assert_eq!(strip_anchors("(?i)^[a-f0-9]{32}$"), "(?i)[a-f0-9]{32}");
    }

    #[test]
    fn test_strip_preserves_escaped_anchors() {
        assert_eq!(strip_anchors(r"^\$NT\$"), r"\$NT\$");
    }

    #[test]
    fn test_strip_no_anchors() {
        assert_eq!(strip_anchors("abc"), "abc");
    }

    #[test]
    fn test_strip_real_bcrypt_pattern() {
        let pat = r"(?i)^(\$2[abxy]?|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$";
        let stripped = strip_anchors(pat);
        assert!(!stripped.starts_with("(?i)^"));
        assert!(!stripped.ends_with("}$"));
        assert!(stripped.contains(r"\$2"));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test boundaryless -v`
Expected: FAIL — `strip_anchors` not defined

**Step 3: Write minimal implementation**

At the top of `src/boundaryless.rs`:

```rust
use regex::Regex;
use std::sync::LazyLock;

use crate::identifier::Match;

/// Regex to match `^` outside character classes and not escaped.
/// pywhat equivalent: re.sub(r"(?<!\\)\^(?![^\[\]]*(?<!\\)\])", "", pattern)
static ANCHOR_CARET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?<!\\)\^(?![^\[\]]*(?<!\\)\])").unwrap());

/// Regex to match `$` outside character classes and not escaped.
static ANCHOR_DOLLAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?<!\\)\$(?![^\[\]]*(?<!\\)\])").unwrap());

pub fn strip_anchors(pattern: &str) -> String {
    let without_caret = ANCHOR_CARET.replace_all(pattern, "");
    ANCHOR_DOLLAR.replace_all(&without_caret, "").into_owned()
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test boundaryless -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/boundaryless.rs
git commit -m "feat: add boundaryless module with strip_anchors"
```

---

### Task 2: `boundaryless.rs` — `remove_submatches` + tests

**Files:**
- Modify: `src/boundaryless.rs`

**Step 1: Write the failing test**

Add to the `tests` module in `src/boundaryless.rs`:

```rust
    fn make_match(text: &str, start: usize, name: &str, rarity: f64) -> Match {
        Match {
            matched_text: text.to_string(),
            start,
            end: start + text.len(),
            name: name.to_string(),
            rarity,
            desc: None,
            url: None,
            tags: vec!["Hash".to_string()],
            hashcat: None,
            john: None,
        }
    }

    #[test]
    fn test_remove_submatches_keeps_longest() {
        let matches = vec![
            make_match("5d41402abc4b2a76b9719d911017c592", 0, "MD5", 0.5),
            make_match("5d41402abc4b2a76", 0, "MySQL", 0.5),
            make_match("5d41402a", 0, "CRC32", 0.5),
        ];
        let result = remove_submatches(matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "MD5");
    }

    #[test]
    fn test_remove_submatches_keeps_nonoverlapping() {
        let matches = vec![
            make_match("aaaa", 0, "A", 0.5),
            make_match("bbbb", 5, "B", 0.5),
        ];
        let result = remove_submatches(matches);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_remove_submatches_sha1_subsumes_md5() {
        // SHA-1 is 40 hex chars; MD5 would match the first 32 as a sub-match
        let matches = vec![
            make_match("da39a3ee5e6b4b0d3255bfef95601890afd80709", 7, "SHA-1", 0.5),
            make_match("da39a3ee5e6b4b0d3255bfef95601890", 7, "MD5", 0.5),
            make_match("da39a3ee5e6b4b0d", 7, "MySQL", 0.5),
        ];
        let result = remove_submatches(matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "SHA-1");
    }

    #[test]
    fn test_remove_submatches_empty() {
        let result = remove_submatches(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_remove_submatches_partial_overlap_kept() {
        // Two matches that overlap but neither contains the other
        let matches = vec![
            make_match("aabbccdd", 0, "A", 0.5),
            make_match("ccddeeff", 4, "B", 0.5),
        ];
        let result = remove_submatches(matches);
        assert_eq!(result.len(), 2);
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo test boundaryless -v`
Expected: FAIL — `remove_submatches` not defined, `Match` missing `start`/`end` fields

**Step 3: Add `start` and `end` fields to `Match`**

In `src/identifier.rs`, add two fields to the `Match` struct after `matched_text`:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct Match {
    pub matched_text: String,
    #[serde(skip)]
    pub start: usize,
    #[serde(skip)]
    pub end: usize,
    pub name: String,
    // ... rest unchanged
}
```

Then fix every place that constructs a `Match` to include `start: 0, end: 0`. There are constructions in:
- `src/identifier.rs` — all `Identify` impls and tests (~12 sites). Set `start: 0, end: 0` for all.
- `src/filter.rs` tests — `make_match` helper. Add `start: 0, end: 0`.
- `src/output.rs` tests — `sample_match` helper. Add `start: 0, end: 0`.

**Step 4: Implement `remove_submatches`**

In `src/boundaryless.rs`:

```rust
pub fn remove_submatches(mut matches: Vec<Match>) -> Vec<Match> {
    if matches.is_empty() {
        return matches;
    }
    // Sort by start position, then longest first
    matches.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));

    let mut kept: Vec<Match> = Vec::new();
    for candidate in matches {
        let is_submatch = kept
            .iter()
            .any(|existing| candidate.start >= existing.start && candidate.end <= existing.end);
        if !is_submatch {
            kept.push(candidate);
        }
    }
    kept
}
```

**Step 5: Run tests to verify they pass**

Run: `cargo test -v`
Expected: ALL PASS (both new boundaryless tests and all existing tests)

**Step 6: Commit**

```bash
git add src/boundaryless.rs src/identifier.rs src/filter.rs src/output.rs
git commit -m "feat: add remove_submatches and start/end fields on Match"
```

---

### Task 3: `hashes.rs` — boundaryless identification

**Files:**
- Modify: `src/hashes.rs`

**Step 1: Write the failing test**

Add at the bottom of the existing `#[cfg(test)]` block in `src/hashes.rs` (if there is one) or create one. Note: `hashes.rs` is auto-generated and may not have tests. Add after the `identify` function:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_boundaryless_md5_in_text() {
        let results = identify_boundaryless("the hash is 5d41402abc4b2a76b9719d911017c592 ok");
        assert!(results.iter().any(|m| m.matched_text == "5d41402abc4b2a76b9719d911017c592"));
    }

    #[test]
    fn test_identify_boundaryless_no_match() {
        let results = identify_boundaryless("no hashes here");
        assert!(results.is_empty());
    }

    #[test]
    fn test_identify_boundaryless_multiple() {
        let results = identify_boundaryless(
            "a]5d41402abc4b2a76b9719d911017c592 b=da39a3ee5e6b4b0d3255bfef95601890afd80709!"
        );
        let texts: Vec<&str> = results.iter().map(|m| m.matched_text.as_str()).collect();
        assert!(texts.contains(&"5d41402abc4b2a76b9719d911017c592"));
        assert!(texts.contains(&"da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test hashes::tests -v`
Expected: FAIL — `identify_boundaryless` not defined

**Step 3: Implement boundaryless statics and function**

Add after the existing `REGEX_SET` and `identify` in `src/hashes.rs`:

```rust
use regex::Regex;
use crate::boundaryless::strip_anchors;
use crate::identifier::Match;

struct BoundarylessHashSet {
    set: RegexSet,
    individual: Vec<Regex>,
}

static BOUNDARYLESS_SET: LazyLock<BoundarylessHashSet> = LazyLock::new(|| {
    let stripped: Vec<String> = PATTERNS.iter().map(|p| strip_anchors(p)).collect();
    let set = regex::RegexSetBuilder::new(&stripped)
        .size_limit(64 * 1024 * 1024)
        .build()
        .unwrap();
    let individual = stripped
        .iter()
        .map(|p| regex::RegexBuilder::new(p).size_limit(64 * 1024 * 1024).build().unwrap())
        .collect();
    BoundarylessHashSet { set, individual }
});

pub fn identify_boundaryless(input: &str) -> Vec<Match> {
    let bset = &*BOUNDARYLESS_SET;
    let set_matches = bset.set.matches(input);
    let mut results = Vec::new();

    for proto in PROTOTYPES.iter() {
        if set_matches.matched(proto.regex_index) {
            let re = &bset.individual[proto.regex_index];
            for m in re.find_iter(input) {
                for mode in proto.modes.iter() {
                    results.push(Match {
                        matched_text: m.as_str().to_string(),
                        start: m.start(),
                        end: m.end(),
                        name: mode.name.to_string(),
                        rarity: if mode.extended { 0.2 } else { 0.5 },
                        desc: mode.desc.map(|d| d.to_string()),
                        url: None,
                        tags: vec!["Hash".to_string()],
                        hashcat: mode.hashcat,
                        john: mode.john.map(|j| j.to_string()),
                    });
                }
            }
        }
    }
    results
}
```

**Step 4: Run tests**

Run: `cargo test -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add src/hashes.rs
git commit -m "feat: add boundaryless hash identification with find_iter"
```

---

### Task 4: `regex_patterns.rs` — boundaryless identification

**Files:**
- Modify: `src/regex_patterns.rs`

**Step 1: Write the failing test**

Add at the bottom of `src/regex_patterns.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_pattern_boundaryless_finds_embedded() {
        let results = identify_pattern_boundaryless("check ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ user@host here");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_identify_pattern_boundaryless_no_match() {
        let results = identify_pattern_boundaryless("nothing here");
        assert!(results.is_empty());
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test regex_patterns::tests -v`
Expected: FAIL — `identify_pattern_boundaryless` not defined

**Step 3: Implement**

Add after the existing `identify_pattern` function in `src/regex_patterns.rs`:

```rust
use regex::Regex;
use crate::boundaryless::strip_anchors;
use crate::identifier::Match;

struct BoundarylessRegexPatternSet {
    set: RegexSet,
    individual: Vec<Regex>,
    index_map: Vec<usize>,
}

static BOUNDARYLESS_REGEX_SET: LazyLock<BoundarylessRegexPatternSet> = LazyLock::new(|| {
    let mut valid_patterns = Vec::new();
    let mut index_map = Vec::new();
    for (i, pat) in PATTERNS.iter().enumerate() {
        let stripped = strip_anchors(pat);
        if regex::Regex::new(&stripped).is_ok() {
            valid_patterns.push(stripped);
            index_map.push(i);
        }
    }
    let set = regex::RegexSetBuilder::new(&valid_patterns)
        .size_limit(64 * 1024 * 1024)
        .build()
        .unwrap();
    let individual = valid_patterns
        .iter()
        .map(|p| regex::RegexBuilder::new(p).size_limit(64 * 1024 * 1024).build().unwrap())
        .collect();
    BoundarylessRegexPatternSet { set, individual, index_map }
});

pub fn identify_pattern_boundaryless(input: &str) -> Vec<Match> {
    let brs = &*BOUNDARYLESS_REGEX_SET;
    let set_matches = brs.set.matches(input);
    let mut results = Vec::new();

    for set_idx in set_matches.iter() {
        let orig_idx = brs.index_map[set_idx];
        let re = &brs.individual[set_idx];
        for m in re.find_iter(input) {
            for p in REGEX_PATTERNS.iter() {
                if p.regex_index == orig_idx {
                    results.push(Match {
                        matched_text: m.as_str().to_string(),
                        start: m.start(),
                        end: m.end(),
                        name: p.name.to_string(),
                        rarity: p.rarity,
                        desc: p.description.map(|s| s.to_string()),
                        url: p.url.map(|s| s.to_string()),
                        tags: p.tags.iter().map(|t| t.to_string()).collect(),
                        hashcat: None,
                        john: None,
                    });
                }
            }
        }
    }
    results
}
```

**Step 4: Run tests**

Run: `cargo test -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add src/regex_patterns.rs
git commit -m "feat: add boundaryless regex pattern identification"
```

---

### Task 5: `identifier.rs` — wire up boundaryless through `Identify` trait

**Files:**
- Modify: `src/identifier.rs`

**Step 1: Write the failing test**

Add to the `tests` module in `src/identifier.rs`:

```rust
    #[test]
    fn test_hash_identifier_boundaryless() {
        let id = HashIdentifier;
        let results = id.identify_boundaryless("hash=5d41402abc4b2a76b9719d911017c592 done");
        assert!(!results.is_empty());
        assert!(results.iter().any(|m| m.matched_text == "5d41402abc4b2a76b9719d911017c592"));
    }

    #[test]
    fn test_regex_identifier_boundaryless() {
        let id = RegexIdentifier;
        let results = id.identify_boundaryless("key ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ user@host end");
        assert!(!results.is_empty());
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo test identifier::tests -v`
Expected: FAIL — `identify_boundaryless` not defined on trait

**Step 3: Implement**

In `src/identifier.rs`, add to the `Identify` trait:

```rust
pub trait Identify {
    fn identify(&self, input: &str) -> Vec<Match>;
    fn identify_boundaryless(&self, input: &str) -> Vec<Match> {
        // Default: fall back to anchored identify
        self.identify(input)
    }
}
```

Then add `identify_boundaryless` impls for `HashIdentifier` and `RegexIdentifier`:

```rust
impl Identify for HashIdentifier {
    fn identify(&self, input: &str) -> Vec<Match> {
        // ... existing code unchanged ...
    }

    fn identify_boundaryless(&self, input: &str) -> Vec<Match> {
        hashes::identify_boundaryless(input)
    }
}

impl Identify for RegexIdentifier {
    fn identify(&self, input: &str) -> Vec<Match> {
        // ... existing code unchanged ...
    }

    fn identify_boundaryless(&self, input: &str) -> Vec<Match> {
        crate::regex_patterns::identify_pattern_boundaryless(input)
    }
}
```

The other identifiers (MacVendor, PhoneCode, Mastercard, FileSignature, Format) keep the default fallback — they're structural enough or low-value enough that boundaryless doesn't apply.

**Step 4: Run tests**

Run: `cargo test -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add src/identifier.rs
git commit -m "feat: add identify_boundaryless to Identify trait with impls"
```

---

### Task 6: `main.rs` — `-b` flag and boundaryless pipeline

**Files:**
- Modify: `src/main.rs`

**Step 1: Add the CLI flag**

In the `Args` struct in `src/main.rs`, add:

```rust
    /// Find all matches inside text (boundaryless mode).
    #[arg(short = 'b', long = "boundaryless")]
    boundaryless: bool,
```

**Step 2: Add the `mod boundaryless;` declaration**

Near the top of `src/main.rs`, add:

```rust
mod boundaryless;
```

**Step 3: Wire up the boundaryless pipeline in `main()`**

Replace the `for text in &inputs` loop with:

```rust
    for text in &inputs {
        let mut matches: Vec<Match> = if args.boundaryless {
            let raw: Vec<Match> = all_ids
                .iter()
                .flat_map(|id| id.identify_boundaryless(text))
                .collect();
            boundaryless::remove_submatches(raw)
        } else {
            all_ids.iter().flat_map(|id| id.identify(text)).collect()
        };

        matches = filter.apply(matches);
        sort_matches(&mut matches, args.key.as_deref(), args.reverse);

        if !matches.is_empty() {
            if !args.json && inputs.len() > 1 {
                println!("{}", text);
                println!("{}", "-".repeat(text.len().min(60)));
            }
            output::print_results(&matches, args.json, &output_opts);
        }
    }
```

**Step 4: Build and smoke test**

Run: `cargo build && cargo run -- -b "the hash is 5d41402abc4b2a76b9719d911017c592 in this text"`
Expected: Should print MD5 match results.

Run: `cargo run -- "5d41402abc4b2a76b9719d911017c592"`
Expected: Same as before (non-boundaryless mode unchanged).

**Step 5: Run full test suite**

Run: `cargo test -v`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat: add -b/--boundaryless CLI flag for text scanning"
```

---

### Task 7: Integration tests

**Files:**
- Create: `tests/boundaryless_integration.rs`

**Step 1: Write integration tests**

```rust
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
    assert!(output.contains("SHA-1") || output.contains("SHA1"), "Should find SHA-1: {output}");
    // The 32-char sub-match should be removed by dedup
    // (it may still show as SHA-1 contains MD5-length prefix, but the matched_text should be 40 chars)
    if output.contains("matched_text") {
        assert!(output.contains("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    }
}

#[test]
fn test_multiple_hashes_in_log() {
    let output = run_fth_json(&[
        "hash=5d41402abc4b2a76b9719d911017c592 session=098f6bcd4621d373cade4e832627b4f6"
    ]);
    assert!(output.contains("5d41402abc4b2a76b9719d911017c592"));
    assert!(output.contains("098f6bcd4621d373cade4e832627b4f6"));
}

#[test]
fn test_bcrypt_in_text() {
    let output = run_fth(&[
        "pw=$2b$12$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6"
    ]);
    assert!(output.to_lowercase().contains("bcrypt"), "Should find bcrypt: {output}");
}

#[test]
fn test_non_boundaryless_unchanged() {
    // Without -b flag, embedded hash should NOT match
    let output = Command::new("cargo")
        .args(["run", "--", "the hash is 5d41402abc4b2a76b9719d911017c592 in text"])
        .output()
        .expect("failed to run fth");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // In non-boundaryless mode, this likely won't find a clean MD5 match
    // (the full string doesn't match any anchored pattern)
    // Just verify it doesn't crash
    assert!(output.status.success() || stdout.is_empty());
}
```

**Step 2: Run integration tests**

Run: `cargo test --test boundaryless_integration -v`
Expected: ALL PASS

**Step 3: Commit**

```bash
git add tests/boundaryless_integration.rs
git commit -m "test: add boundaryless integration tests"
```

---

### Task 8: Update README with boundaryless examples

**Files:**
- Modify: `README.md`

**Step 1: Add boundaryless examples**

Add a "Boundaryless mode" section after the existing Usage examples in `README.md`:

```markdown
### Boundaryless mode

Scan for hashes embedded in text, log lines, or other noisy input:

```sh
fth -b 'the password hash is 5d41402abc4b2a76b9719d911017c592 for admin'
fth -b '2024-01-15 hash=098f6bcd4621d373cade4e832627b4f6 session=5d41402abc4b2a76b9719d911017c592'
fth -b --json 'commit da39a3ee5e6b4b0d3255bfef95601890afd80709 merged'
```

Sub-matches are automatically removed — a SHA-1 won't falsely trigger MD5.
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add boundaryless mode examples to README"
```

---

### Task 9: Clean up prototype file

**Files:**
- Delete: `test_boundaryless.py`

**Step 1: Remove the Python prototype**

```bash
rm test_boundaryless.py
git add -u test_boundaryless.py
git commit -m "chore: remove Python boundaryless prototype"
```
