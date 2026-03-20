use serde::Serialize;

use crate::hashes;

#[derive(Debug, Clone, Serialize)]
pub struct Match {
    pub matched_text: String,
    #[serde(skip)]
    pub start: usize,
    #[serde(skip)]
    pub end: usize,
    pub name: String,
    pub rarity: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashcat: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub john: Option<String>,
}

pub trait Identify: Send + Sync {
    fn identify(&self, input: &str) -> Vec<Match>;
    fn identify_boundaryless(&self, input: &str) -> Vec<Match> {
        self.identify(input)
    }
}

pub struct FormatIdentifier;
pub struct HashIdentifier;
pub struct MastercardIdentifier;
pub struct RegexIdentifier;
pub struct MacVendorIdentifier;
pub struct PhoneCodeIdentifier;
pub struct FileSignatureIdentifier;

impl Identify for FormatIdentifier {
    fn identify(&self, input: &str) -> Vec<Match> {
        crate::formats::identify_format(input)
            .into_iter()
            .map(|f| Match {
                matched_text: input.to_string(),
                start: 0,
                end: 0,
                name: f.name,
                rarity: f.rarity,
                desc: Some(f.desc),
                url: None,
                tags: f.tags,
                hashcat: f.hashcat,
                john: f.john,
            })
            .collect()
    }
}

impl Identify for HashIdentifier {
    fn identify(&self, input: &str) -> Vec<Match> {
        hashes::identify(input)
            .into_iter()
            .map(|h| Match {
                matched_text: input.to_string(),
                start: 0,
                end: 0,
                name: h.name.to_string(),
                rarity: if h.extended { 0.2 } else { 0.5 },
                desc: h.desc.map(|d| d.to_string()),
                url: None,
                tags: vec!["Hash".to_string()],
                hashcat: h.hashcat,
                john: h.john.map(|j| j.to_string()),
            })
            .collect()
    }

    fn identify_boundaryless(&self, input: &str) -> Vec<Match> {
        hashes::identify_boundaryless(input)
    }
}
impl Identify for RegexIdentifier {
    fn identify(&self, input: &str) -> Vec<Match> {
        crate::regex_patterns::identify_pattern(input)
            .into_iter()
            .map(|p| Match {
                matched_text: input.to_string(),
                start: 0,
                end: 0,
                name: p.name.to_string(),
                rarity: p.rarity,
                desc: p.description.map(|s| s.to_string()),
                url: p.url.map(|s| s.to_string()),
                tags: p.tags.iter().map(|t| t.to_string()).collect(),
                hashcat: None,
                john: None,
            })
            .collect()
    }

    fn identify_boundaryless(&self, input: &str) -> Vec<Match> {
        crate::regex_patterns::identify_pattern_boundaryless(input)
    }
}

impl Identify for MacVendorIdentifier {
    fn identify(&self, input: &str) -> Vec<Match> {
        // Only try if input looks like a MAC address (hex + separators)
        let hex_count = input.chars().filter(|c| c.is_ascii_hexdigit()).count();
        let sep_count = input.chars().filter(|&c| c == ':' || c == '-' || c == '.').count();
        if hex_count < 6 || hex_count + sep_count != input.len() {
            return vec![];
        }
        match crate::mac_vendors::lookup_mac_vendor(input) {
            Some(vendor) => vec![Match {
                matched_text: input.to_string(),
                start: 0,
                end: 0,
                name: format!("MAC Address ({})", vendor),
                rarity: 0.5,
                desc: Some(format!("Vendor: {}", vendor)),
                url: None,
                tags: vec!["Network".to_string()],
                hashcat: None,
                john: None,
            }],
            None => vec![],
        }
    }
}

impl Identify for PhoneCodeIdentifier {
    fn identify(&self, input: &str) -> Vec<Match> {
        if !input.starts_with('+') {
            return vec![];
        }
        match crate::phone_codes::lookup_phone_code(input) {
            Some(country) => vec![Match {
                matched_text: input.to_string(),
                start: 0,
                end: 0,
                name: format!("Phone Code ({})", country),
                rarity: 0.5,
                desc: Some(format!("Country: {}", country)),
                url: None,
                tags: vec!["Phone".to_string()],
                hashcat: None,
                john: None,
            }],
            None => vec![],
        }
    }
}

impl Identify for MastercardIdentifier {
    fn identify(&self, input: &str) -> Vec<Match> {
        // Only try if input looks like a card number (digits with optional spaces/dashes)
        let digits: String = input.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() < 6
            || digits.len() > 19
            || !input
                .chars()
                .all(|c| c.is_ascii_digit() || c == ' ' || c == '-')
        {
            return vec![];
        }
        match crate::mastercard::lookup_mastercard(&digits) {
            Some(company) => vec![Match {
                matched_text: input.to_string(),
                start: 0,
                end: 0,
                name: format!("Mastercard ({})", company),
                rarity: 0.5,
                desc: Some(format!("Issuer: {}", company)),
                url: None,
                tags: vec!["Financial".to_string()],
                hashcat: None,
                john: None,
            }],
            None => vec![],
        }
    }
}

impl Identify for FileSignatureIdentifier {
    fn identify(&self, input: &str) -> Vec<Match> {
        // Only try if input looks like a hex string
        if input.len() < 4 || !input.chars().all(|c| c.is_ascii_hexdigit()) {
            return vec![];
        }
        crate::file_signatures::identify_file(input)
            .into_iter()
            .map(|sig| Match {
                matched_text: input.to_string(),
                start: 0,
                end: 0,
                name: sig.desc.to_string(),
                rarity: if sig.popular { 0.5 } else { 0.3 },
                desc: sig.extension.map(|e| format!("Extension: .{}", e)),
                url: sig.url.map(|s| s.to_string()),
                tags: vec!["File Signature".to_string()],
                hashcat: None,
                john: None,
            })
            .collect()
    }
}

pub fn all_identifiers() -> Vec<Box<dyn Identify + Send + Sync>> {
    vec![
        Box::new(FormatIdentifier),  // Format detection first (highest confidence)
        Box::new(HashIdentifier),
        Box::new(MastercardIdentifier),
        Box::new(RegexIdentifier),
        Box::new(MacVendorIdentifier),
        Box::new(PhoneCodeIdentifier),
        Box::new(FileSignatureIdentifier),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    struct DummyIdentifier;

    #[test]
    fn test_match_default_fields() {
        let m = Match {
            matched_text: "test".into(),
            start: 0,
            end: 0,
            name: "Test Match".into(),
            rarity: 0.5,
            desc: None,
            url: None,
            tags: vec!["Test".into()],
            hashcat: None,
            john: None,
        };
        assert_eq!(m.name, "Test Match");
        assert_eq!(m.rarity, 0.5);
        assert!(m.tags.contains(&"Test".to_string()));
    }

    impl Identify for DummyIdentifier {
        fn identify(&self, input: &str) -> Vec<Match> {
            if input == "hello" {
                vec![Match {
                    matched_text: input.into(),
                    start: 0,
                    end: 0,
                    name: "Greeting".into(),
                    rarity: 1.0,
                    desc: None,
                    url: None,
                    tags: vec![],
                    hashcat: None,
                    john: None,
                }]
            } else {
                vec![]
            }
        }
    }

    #[test]
    fn test_identify_trait_dispatch() {
        let identifiers: Vec<Box<dyn Identify + Send + Sync>> = vec![Box::new(DummyIdentifier)];
        let results: Vec<Match> = identifiers
            .iter()
            .flat_map(|id| id.identify("hello"))
            .collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Greeting");

        let empty: Vec<Match> = identifiers
            .iter()
            .flat_map(|id| id.identify("nope"))
            .collect();
        assert!(empty.is_empty());
    }

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

    #[test]
    fn test_hash_identifier_md5() {
        let id = HashIdentifier;
        let results = id.identify("5d41402abc4b2a76b9719d911017c592");
        assert!(!results.is_empty());
        assert!(
            results
                .iter()
                .any(|m| m.name.to_lowercase().contains("md5"))
        );
        assert!(results.iter().all(|m| m.tags.contains(&"Hash".to_string())));
    }

    #[test]
    fn test_hash_identifier_no_match() {
        let id = HashIdentifier;
        let results = id.identify("not a hash at all");
        assert!(results.is_empty());
    }

    #[test]
    fn test_regex_identifier_ssh_key() {
        let id = RegexIdentifier;
        let results = id.identify("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ user@host");
        // Should match SSH RSA Public Key pattern
        assert!(!results.is_empty());
    }

    #[test]
    fn test_mac_vendor_identifier() {
        let id = MacVendorIdentifier;
        // F8:8F:CA is Google
        let results = id.identify("F8:8F:CA:00:11:22");
        assert!(!results.is_empty());
        assert!(results[0].name.contains("Google"));
        assert!(results[0].tags.contains(&"Network".to_string()));
    }

    #[test]
    fn test_mac_vendor_no_match() {
        let id = MacVendorIdentifier;
        let results = id.identify("hello world");
        assert!(results.is_empty());
    }

    #[test]
    fn test_phone_code_identifier() {
        let id = PhoneCodeIdentifier;
        let results = id.identify("+93");
        assert!(!results.is_empty());
        assert!(results[0].name.contains("Afghanistan"));
    }

    #[test]
    fn test_phone_code_no_match() {
        let id = PhoneCodeIdentifier;
        let results = id.identify("hello");
        assert!(results.is_empty());
    }

    #[test]
    fn test_mastercard_identifier() {
        let id = MastercardIdentifier;
        // 551411 is "STAR PROCESSING, INC." from the data
        let results = id.identify("5514110000000000");
        assert!(!results.is_empty());
        assert!(results[0].tags.contains(&"Financial".to_string()));
    }

    #[test]
    fn test_mastercard_no_match() {
        let id = MastercardIdentifier;
        let results = id.identify("hello");
        assert!(results.is_empty());
    }

    #[test]
    fn test_file_signature_identifier() {
        let id = FileSignatureIdentifier;
        // "2321" is shebang (#!)
        let results = id.identify("2321");
        assert!(!results.is_empty());
        assert!(results[0].tags.contains(&"File Signature".to_string()));
    }

    #[test]
    fn test_all_identifiers_dispatch() {
        let identifiers: Vec<Box<dyn Identify + Send + Sync>> = all_identifiers();
        let results: Vec<Match> = identifiers
            .iter()
            .flat_map(|id| id.identify("5d41402abc4b2a76b9719d911017c592"))
            .collect();
        // Should get hash matches at minimum
        assert!(!results.is_empty());
    }

    #[test]
    fn test_format_identifier_pwdump() {
        let id = FormatIdentifier;
        let results = id.identify("Jason:502:aad3c435b514a4eeaad3b935b51304fe:c46b9e588fa0d112de6f59fd6d58eae3:::");
        assert!(!results.is_empty(), "FormatIdentifier should match pwdump");
        assert!(results.iter().any(|m| m.name == "NTLM"));
        assert!(results[0].rarity > 0.8, "format matches should have high confidence");
    }

    #[test]
    fn test_format_identifier_shadow() {
        let id = FormatIdentifier;
        let results = id.identify("root:$6$qdMgClgO2dQWB37F$jhexCX1SdsCAi0OZmoRVAPnWSwuP/mHVhXIMJfKlaacxFkwWLDZ0ViF8Ur3WcHashcatVp2WShcEILi8QZCbt/:19000:0:99999:7:::");
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "SHA-512 Crypt");
    }

    #[test]
    fn test_all_identifiers_includes_format() {
        let ids = all_identifiers();
        let results: Vec<Match> = ids.iter().flat_map(|id| id.identify("Jason:502:aad3c435b514a4eeaad3b935b51304fe:c46b9e588fa0d112de6f59fd6d58eae3:::")).collect();
        assert!(results.iter().any(|m| m.name == "NTLM" && m.rarity > 0.8));
    }
}
