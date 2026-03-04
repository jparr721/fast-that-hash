use regex::Regex;
use std::sync::LazyLock;

pub struct FormatMatch {
    pub name: String,
    pub rarity: f64,
    pub desc: String,
    pub extracted_hash: String,
    pub tags: Vec<String>,
    pub hashcat: Option<u32>,
    pub john: Option<String>,
}

struct Format {
    name: &'static str,
    regex: &'static LazyLock<Regex>,
    extract: fn(&regex::Captures) -> Vec<FormatMatch>,
}

// pwdump: user:RID:LM_hash:NT_hash:::
static PWDUMP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^[^:]+:\d+:([a-f0-9]{32}):([a-f0-9]{32}):::?$").unwrap()
});

fn extract_pwdump(caps: &regex::Captures) -> Vec<FormatMatch> {
    let lm_hash = caps[1].to_string();
    let ntlm_hash = caps[2].to_string();
    vec![
        FormatMatch {
            name: "NTLM".to_string(),
            rarity: 0.9,
            desc: "Windows NTLM hash extracted from pwdump format.".to_string(),
            extracted_hash: ntlm_hash,
            tags: vec!["Hash".to_string()],
            hashcat: Some(1000),
            john: Some("nt".to_string()),
        },
        FormatMatch {
            name: "LM".to_string(),
            rarity: 0.9,
            desc: "LAN Manager hash extracted from pwdump format.".to_string(),
            extracted_hash: lm_hash,
            tags: vec!["Hash".to_string()],
            hashcat: Some(3000),
            john: Some("lm".to_string()),
        },
    ]
}

static FORMATS: &[Format] = &[
    Format {
        name: "pwdump",
        regex: &PWDUMP_RE,
        extract: extract_pwdump,
    },
];

pub fn identify_format(input: &str) -> Vec<FormatMatch> {
    for fmt in FORMATS {
        if let Some(caps) = fmt.regex.captures(input) {
            return (fmt.extract)(&caps);
        }
    }
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pwdump_standard() {
        let input = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b:::";
        let results = identify_format(input);
        assert!(!results.is_empty(), "pwdump format should match");
        assert!(
            results.iter().any(|m| m.name == "NTLM"),
            "should identify NTLM hash"
        );
        assert!(
            results.iter().any(|m| m.name == "LM"),
            "should identify LM hash"
        );
        let ntlm = results.iter().find(|m| m.name == "NTLM").unwrap();
        assert_eq!(ntlm.hashcat, Some(1000));
        assert_eq!(ntlm.john.as_deref(), Some("nt"));
        assert!((ntlm.rarity - 0.9).abs() < f64::EPSILON);
        assert_eq!(ntlm.extracted_hash, "b4b9b02e6f09a9bd760f388b67351e2b");
    }

    #[test]
    fn test_pwdump_user_example() {
        let input = "Jason:502:aad3c435b514a4eeaad3b935b51304fe:c46b9e588fa0d112de6f59fd6d58eae3:::";
        let results = identify_format(input);
        assert!(results.iter().any(|m| m.name == "NTLM"));
        let ntlm = results.iter().find(|m| m.name == "NTLM").unwrap();
        assert_eq!(ntlm.extracted_hash, "c46b9e588fa0d112de6f59fd6d58eae3");
    }

    #[test]
    fn test_pwdump_no_match_raw_hash() {
        let input = "b4b9b02e6f09a9bd760f388b67351e2b";
        let results = identify_format(input);
        assert!(results.is_empty(), "raw hash should not match pwdump format");
    }
}
