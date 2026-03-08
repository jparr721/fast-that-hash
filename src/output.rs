use crate::identifier::Match;
use colored::Colorize;

/// Options controlling which extra fields appear in pretty output.
pub struct OutputOpts {
    /// Include John The Ripper mode strings in output.
    pub show_john: bool,
    /// Include Hashcat mode numbers in output.
    pub show_hashcat: bool,
}

/// Serialise `matches` as a pretty-printed JSON array.
///
/// Returns the string `"[]"` on serialisation failure so callers always receive
/// valid JSON without having to handle an error themselves.
///
/// # Examples
///
/// ```rust
/// use fast_that_hash::identifier::Match;
/// use fast_that_hash::output::format_json;
///
/// let m = Match {
///     matched_text: "abc".into(),
///     start: 0,
///     end: 0,
///     name: "Example".into(),
///     rarity: 1.0,
///     desc: None,
///     url: None,
///     tags: vec![],
///     hashcat: None,
///     john: None,
/// };
/// let json = format_json(&[m]);
/// assert!(json.contains("\"name\""));
/// ```
pub fn format_json(matches: &[Match]) -> String {
    serde_json::to_string_pretty(matches).unwrap_or_else(|_| "[]".to_string())
}

/// Format `matches` for human-readable terminal output.
///
/// The rarity label is coloured green (>= 0.7), yellow (>= 0.4), or red (<
/// 0.4).  Additional fields are included based on `opts`.
///
/// # Examples
///
/// ```rust
/// use fast_that_hash::identifier::Match;
/// use fast_that_hash::output::{format_pretty, OutputOpts};
///
/// let m = Match {
///     matched_text: "abc".into(),
///     start: 0,
///     end: 0,
///     name: "Example".into(),
///     rarity: 0.8,
///     desc: Some("An example match".into()),
///     url: None,
///     tags: vec!["Test".into()],
///     hashcat: None,
///     john: None,
/// };
/// let opts = OutputOpts { show_john: false, show_hashcat: false };
/// let output = format_pretty(&[m], &opts);
/// assert!(output.contains("Example"));
/// ```
pub fn format_pretty(matches: &[Match], opts: &OutputOpts) -> String {
    let mut out = String::new();
    for m in matches {
        out.push_str(&format!("[{}] {}\n", format_rarity(m.rarity), m.name.bold()));
        if let Some(ref desc) = m.desc {
            out.push_str(&format!("  {}\n", desc));
        }
        if !m.tags.is_empty() {
            out.push_str(&format!("  Tags: {}\n", m.tags.join(", ").dimmed()));
        }
        if let Some(ref url) = m.url {
            out.push_str(&format!("  URL: {}\n", url.underline()));
        }
        if opts.show_hashcat {
            if let Some(hc) = m.hashcat {
                out.push_str(&format!("  Hashcat: {}\n", hc));
            }
        }
        if opts.show_john {
            if let Some(ref j) = m.john {
                out.push_str(&format!("  John: {}\n", j));
            }
        }
        out.push('\n');
    }
    out
}

/// Colour-code a rarity value and return it as a [`colored::ColoredString`].
fn format_rarity(rarity: f64) -> colored::ColoredString {
    let label = format!("{:.1}", rarity);
    if rarity >= 0.7 {
        label.green()
    } else if rarity >= 0.4 {
        label.yellow()
    } else {
        label.red()
    }
}

/// Print results to stdout in either JSON or pretty format.
///
/// When `json` is `true` the output is a pretty-printed JSON array.  Otherwise
/// the human-readable pretty format is used, governed by `opts`.
pub fn print_results(matches: &[Match], json: bool, opts: &OutputOpts) {
    if json {
        println!("{}", format_json(matches));
    } else {
        print!("{}", format_pretty(matches, opts));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifier::Match;

    fn sample_match() -> Match {
        Match {
            matched_text: "5d41402abc4b2a76b9719d911017c592".into(),
            start: 0,
            end: 0,
            name: "MD5".into(),
            rarity: 0.5,
            desc: Some("MD5 hash".into()),
            url: None,
            tags: vec!["Hash".into()],
            hashcat: Some(0),
            john: Some("raw-md5".into()),
        }
    }

    #[test]
    fn test_json_output() {
        let matches = vec![sample_match()];
        let json = format_json(&matches);
        assert!(json.contains("\"name\":"));
        assert!(json.contains("MD5"));
        assert!(json.contains("\"hashcat\":"));
    }

    #[test]
    fn test_pretty_output_contains_name() {
        let matches = vec![sample_match()];
        let opts = OutputOpts {
            show_john: true,
            show_hashcat: true,
        };
        let output = format_pretty(&matches, &opts);
        assert!(output.contains("MD5"));
    }

    #[test]
    fn test_pretty_output_hides_john() {
        let matches = vec![sample_match()];
        let opts = OutputOpts {
            show_john: false,
            show_hashcat: true,
        };
        let output = format_pretty(&matches, &opts);
        assert!(!output.contains("raw-md5"));
    }
}
