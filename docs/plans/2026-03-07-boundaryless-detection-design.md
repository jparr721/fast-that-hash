# Boundaryless Hash Detection

## Problem

All hash/regex patterns use `^`/`$` anchors, requiring each input string to be exactly one hash. Input like `"the hash is 5d41402abc4b2a76b9719d911017c592 in text"` finds nothing.

## Approach: Strip Anchors + Post-Process Overlap Removal

Inspired by pywhat's `helper.py:load_regexes()` which dynamically strips `^`/`$` from patterns. We add a post-processing step to remove sub-matches (matches fully contained within a longer match at an overlapping position).

### Why not hex-boundary assertions?

We prototyped replacing `^`/`$` with `(?<![a-fA-F0-9])`/`(?![a-fA-F0-9])` for hex-dominant patterns. Problems:
- Requires classifying patterns as "hex-dominant" — a heuristic with edge cases (optional prefixes like `(\$NT\$)?[a-f0-9]{32}`, mixed charsets like `[a-z0-9]`)
- Broader charset patterns (DES Crypt `[a-z0-9\/.]{13}`) need different boundary chars
- Post-process dedup solves the same problem without pattern classification

### Why not just strip like pywhat?

Stripping alone produces massive noise. A 32-char MD5 in text generates CRC32, ObjectID, MySQL sub-matches. A 40-char SHA-1 falsely triggers MD5. Our prototype showed 297 raw matches reduced to 112 with dedup — 62% noise reduction.

## Design

### Pattern Transformation

Strip `^` and `$` outside character classes (identical to pywhat):

```rust
fn strip_anchors(pattern: &str) -> String
```

Regex: remove `^` not preceded by `\` and not inside `[...]`. Same for `$`.

### Overlap Removal

After collecting all `(matched_text, start, end, pattern_name)` tuples:

1. Sort by start position, then by length descending (longest first)
2. For each candidate, check if it's fully contained within any already-kept match
3. If contained, discard it; otherwise keep it

```rust
fn remove_submatches(matches: Vec<BoundarylessMatch>) -> Vec<BoundarylessMatch>
```

This is O(n*k) where n = candidates, k = kept matches. Both are tiny in practice.

### Architecture Changes

**New module: `src/boundaryless.rs`**
- `strip_anchors(pattern: &str) -> String`
- `remove_submatches(matches: &mut Vec<BoundarylessMatch>)`
- `BoundarylessMatch` struct: `{ text, start, end, name, rarity, ... }`

**Changes to `src/hashes.rs`**
- New `LazyLock<RegexSet>` for boundaryless patterns (stripped anchors)
- New `LazyLock<Vec<Regex>>` for individual patterns (needed for `find_iter`)
- New `pub fn identify_boundaryless(input: &str) -> Vec<BoundarylessMatch>`
  - Uses `RegexSet::matches()` to find which patterns hit
  - Runs `Regex::find_iter()` only on hit patterns to extract positions

**Changes to `src/regex_patterns.rs`**
- Same pattern: boundaryless `RegexSet` + individual `Regex` vec + `identify_pattern_boundaryless()`

**Changes to `src/formats.rs`**
- Formats already have enough structure; strip anchors and use `find_iter` directly

**Changes to `src/identifier.rs`**
- `Identify` trait gets `fn identify_boundaryless(&self, input: &str) -> Vec<Match>` with default falling back to `identify()`
- Each identifier implements boundaryless variant

**Changes to `src/main.rs`**
- New `--boundaryless` / `-b` CLI flag
- When enabled, calls `identify_boundaryless()` instead of `identify()`, then runs `remove_submatches()` on the collected results before filtering/output

### Match Deduplication Flow

```
input text
  -> each identifier runs find_iter with stripped patterns
  -> collect all (text, start, end, pattern_info) tuples
  -> remove_submatches(): drop matches contained within longer matches
  -> apply rarity/tag filters
  -> sort and output
```

### What changes for existing (non-boundaryless) mode

Nothing. The existing anchored `RegexSet` and `identify()` functions remain untouched. Boundaryless is opt-in via `-b`.

## Validation

Prototype tested in `test_boundaryless.py` with 22 test cases. Key results:
- MD5 in sentence: 11 raw -> 1 after dedup
- SHA-1 in text: MD5 sub-match correctly removed
- 64-char hex blob: 25 raw -> 1 SHA-256
- Two separate MD5s: both kept
- bcrypt/LDAP SHA/MD5 Crypt: all found in text
- All 8 validation checks passed
