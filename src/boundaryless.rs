use crate::identifier::Match;

/// Remove matches whose span `[start, end)` is fully contained within the span
/// of an already-kept match.
///
/// The input is sorted by `start` ascending, then `end` descending so that the
/// longest match at any given position is encountered first and shorter
/// sub-matches are discarded.
///
/// # Behaviour
///
/// Given two matches where one's `[start, end)` interval is fully contained
/// within the other's, the contained (shorter) match is dropped and only the
/// longer match is kept.  Matches that partially overlap or share no overlap
/// are both retained.
pub fn remove_submatches(mut matches: Vec<Match>) -> Vec<Match> {
    if matches.is_empty() {
        return matches;
    }
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

/// Remove unescaped `^` and `$` anchors from a regex pattern, preserving
/// them inside character classes (`[...]`) and when escaped (`\^`, `\$`).
pub fn strip_anchors(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut result = String::with_capacity(pattern.len());
    let mut i = 0;
    let mut in_char_class = false;

    while i < chars.len() {
        let ch = chars[i];

        if ch == '\\' {
            // Escaped character — always keep both the backslash and the next char.
            result.push(ch);
            if i + 1 < chars.len() {
                i += 1;
                result.push(chars[i]);
            }
            i += 1;
            continue;
        }

        if ch == '[' && !in_char_class {
            in_char_class = true;
            result.push(ch);
            i += 1;
            continue;
        }

        if ch == ']' && in_char_class {
            in_char_class = false;
            result.push(ch);
            i += 1;
            continue;
        }

        if !in_char_class && (ch == '^' || ch == '$') {
            // Strip unescaped anchor outside character class.
            i += 1;
            continue;
        }

        result.push(ch);
        i += 1;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifier::Match;

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
        let matches = vec![
            make_match("aabbccdd", 0, "A", 0.5),
            make_match("ccddeeff", 4, "B", 0.5),
        ];
        let result = remove_submatches(matches);
        assert_eq!(result.len(), 2);
    }

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
