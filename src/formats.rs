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
    _name: &'static str,
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

// /etc/shadow line: user:$id$...:rest_of_fields
static SHADOW_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([^:]+):(\$[^:]+):\d").unwrap()
});

fn extract_shadow(caps: &regex::Captures) -> Vec<FormatMatch> {
    let hash = caps[2].to_string();
    let (name, hashcat, john) = if hash.starts_with("$6$") {
        ("SHA-512 Crypt", Some(1800_u32), Some("sha512crypt"))
    } else if hash.starts_with("$5$") {
        ("SHA-256 Crypt", Some(7400), Some("sha256crypt"))
    } else if hash.starts_with("$1$") {
        ("MD5 Crypt", Some(500), Some("md5crypt"))
    } else if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
        ("bcrypt", Some(3200), Some("bcrypt"))
    } else if hash.starts_with("$y$") {
        ("yescrypt", None, Some("yescrypt"))
    } else {
        return vec![];
    };
    vec![FormatMatch {
        name: name.to_string(),
        rarity: 0.9,
        desc: format!("{} hash extracted from /etc/shadow line.", name),
        extracted_hash: hash,
        tags: vec!["Hash".to_string()],
        hashcat,
        john: john.map(|j| j.to_string()),
    }]
}

// DCC: 32hex:username (where username is NOT all hex)
static DCC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^([a-f0-9]{32}):([^:]+)$").unwrap()
});

fn extract_dcc(caps: &regex::Captures) -> Vec<FormatMatch> {
    let hash = caps[1].to_string();
    let username = &caps[2];
    // Only match if the second part looks like a username (not all hex)
    if username.chars().all(|c| c.is_ascii_hexdigit()) && username.len() >= 16 {
        return vec![]; // Probably hash:hash, not hash:username
    }
    vec![FormatMatch {
        name: "Domain Cached Credentials".to_string(),
        rarity: 0.9,
        desc: format!("DCC hash for user '{}' (MS Cache Hash v1).", username),
        extracted_hash: hash,
        tags: vec!["Hash".to_string()],
        hashcat: Some(1100),
        john: Some("mscash".to_string()),
    }]
}

static FORMATS: &[Format] = &[
    Format {
        _name: "pwdump",
        regex: &PWDUMP_RE,
        extract: extract_pwdump,
    },
    Format {
        _name: "shadow",
        regex: &SHADOW_RE,
        extract: extract_shadow,
    },
    Format {
        _name: "dcc",
        regex: &DCC_RE,
        extract: extract_dcc,
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

    #[test]
    fn test_shadow_sha512() {
        let input = "root:$6$qdMgClgO2dQWB37F$jhexCX1SdsCAi0OZmoRVAPnWSwuP/mHVhXIMJfKlaacxFkwWLDZ0ViF8Ur3WcHashcatVp2WShcEILi8QZCbt/:19000:0:99999:7:::";
        let results = identify_format(input);
        assert!(!results.is_empty(), "shadow line should match");
        let m = &results[0];
        assert_eq!(m.name, "SHA-512 Crypt");
        assert_eq!(m.hashcat, Some(1800));
        assert!(m.extracted_hash.starts_with("$6$"));
    }

    #[test]
    fn test_shadow_sha256() {
        let input = "user:$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD:19000:0:99999:7:::";
        let results = identify_format(input);
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "SHA-256 Crypt");
        assert_eq!(results[0].hashcat, Some(7400));
    }

    #[test]
    fn test_shadow_md5crypt() {
        let input = "user:$1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1:19000:0:99999:7:::";
        let results = identify_format(input);
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "MD5 Crypt");
        assert_eq!(results[0].hashcat, Some(500));
    }

    #[test]
    fn test_shadow_bcrypt() {
        let input = "user:$2b$12$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6:19000:0:99999:7:::";
        let results = identify_format(input);
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "bcrypt");
        assert_eq!(results[0].hashcat, Some(3200));
    }

    #[test]
    fn test_shadow_yescrypt() {
        let input = "user:$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X3DX6M94c7o.9agCG9G317fhZg9SqC.5i5rd.RhAtQ7:19000:0:99999:7:::";
        let results = identify_format(input);
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "yescrypt");
    }

    #[test]
    fn test_shadow_no_match_bare_hash() {
        let input = "$6$qdMgClgO2dQWB37F$jhexCX1SdsCAi0OZmoRVAPnWSwuP/mHVhXIMJfKlaacxFkwWLDZ0ViF8Ur3WcHashcatVp2WShcEILi8QZCbt/";
        let results = identify_format(input);
        assert!(results.is_empty(), "bare shadow hash (no user: prefix) should not match format parser");
    }

    #[test]
    fn test_dcc_hash_username() {
        let input = "4dd8965d1d476fa0d026722989a6b772:3060147285011";
        let results = identify_format(input);
        assert!(!results.is_empty(), "DCC hash:username format should match");
        assert_eq!(results[0].name, "Domain Cached Credentials");
        assert_eq!(results[0].hashcat, Some(1100));
        assert_eq!(results[0].extracted_hash, "4dd8965d1d476fa0d026722989a6b772");
    }

    #[test]
    fn test_dcc_no_match_ntlmv2() {
        // NetNTLMv2 contains colons too but has a different structure
        let input = "admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030";
        let results = identify_format(input);
        assert!(results.is_empty() || !results.iter().any(|m| m.name.contains("Domain Cached")));
    }

    #[test]
    fn test_raw_md5_not_matched_by_format() {
        let results = identify_format("8743b52063cd84097a65d1633f5c74f5");
        assert!(results.is_empty());
    }

    #[test]
    fn test_raw_ntlm_not_matched_by_format() {
        let results = identify_format("CD06CA7C7E10C99B1D33B7485A2ED808");
        assert!(results.is_empty());
    }

    #[test]
    fn test_bcrypt_standalone_not_matched_by_format() {
        let results = identify_format("$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6");
        assert!(results.is_empty(), "standalone bcrypt should be handled by HashIdentifier, not format parser");
    }

    #[test]
    fn test_netntlmv1_not_matched_by_format() {
        let results = identify_format("u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c");
        assert!(results.is_empty(), "NetNTLMv1 is already handled by HashIdentifier");
    }
}
