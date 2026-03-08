#[allow(unused_imports)]
use crate::identifier::Match;

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
