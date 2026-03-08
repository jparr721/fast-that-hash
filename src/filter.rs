use crate::identifier::Match;

pub struct Filter {
    pub rarity_min: f64,
    pub rarity_max: f64,
    pub include_tags: Option<Vec<String>>,
    pub exclude_tags: Option<Vec<String>>,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            rarity_min: 0.1,
            rarity_max: 1.0,
            include_tags: None,
            exclude_tags: None,
        }
    }
}

impl Filter {
    pub fn apply(&self, matches: Vec<Match>) -> Vec<Match> {
        matches
            .into_iter()
            .filter(|m| m.rarity >= self.rarity_min && m.rarity <= self.rarity_max)
            .filter(|m| {
                if let Some(ref include) = self.include_tags {
                    m.tags.iter().any(|t| include.iter().any(|inc| t.eq_ignore_ascii_case(inc)))
                } else {
                    true
                }
            })
            .filter(|m| {
                if let Some(ref exclude) = self.exclude_tags {
                    !m.tags.iter().any(|t| exclude.iter().any(|exc| t.eq_ignore_ascii_case(exc)))
                } else {
                    true
                }
            })
            .collect()
    }
}

pub fn parse_rarity_range(s: &str) -> Result<(f64, f64), String> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid rarity range '{}', expected format 'min:max'", s));
    }
    let min = if parts[0].is_empty() {
        0.0
    } else {
        parts[0].parse::<f64>().map_err(|e| format!("Invalid min rarity: {}", e))?
    };
    let max = if parts[1].is_empty() {
        1.0
    } else {
        parts[1].parse::<f64>().map_err(|e| format!("Invalid max rarity: {}", e))?
    };
    Ok((min, max))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifier::Match;

    fn make_match(name: &str, rarity: f64, tags: Vec<&str>) -> Match {
        Match {
            matched_text: "test".into(),
            start: 0,
            end: 0,
            name: name.into(),
            rarity,
            desc: None,
            url: None,
            tags: tags.into_iter().map(String::from).collect(),
            hashcat: None,
            john: None,
        }
    }

    #[test]
    fn test_parse_rarity_range_full() {
        let (min, max) = parse_rarity_range("0.1:1").unwrap();
        assert!((min - 0.1).abs() < f64::EPSILON);
        assert!((max - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_rarity_range_min_only() {
        let (min, max) = parse_rarity_range("0.5:").unwrap();
        assert!((min - 0.5).abs() < f64::EPSILON);
        assert!((max - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_rarity_range_max_only() {
        let (min, max) = parse_rarity_range(":0.8").unwrap();
        assert!(min.abs() < f64::EPSILON);
        assert!((max - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_filter_by_rarity() {
        let filter = Filter {
            rarity_min: 0.4,
            rarity_max: 1.0,
            include_tags: None,
            exclude_tags: None,
        };
        let matches = vec![
            make_match("Low", 0.2, vec!["Hash"]),
            make_match("High", 0.8, vec!["Hash"]),
        ];
        let result = filter.apply(matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "High");
    }

    #[test]
    fn test_filter_include_tags() {
        let filter = Filter {
            rarity_min: 0.0,
            rarity_max: 1.0,
            include_tags: Some(vec!["Network".into()]),
            exclude_tags: None,
        };
        let matches = vec![
            make_match("A", 0.5, vec!["Hash"]),
            make_match("B", 0.5, vec!["Network"]),
        ];
        let result = filter.apply(matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "B");
    }

    #[test]
    fn test_filter_exclude_tags() {
        let filter = Filter {
            rarity_min: 0.0,
            rarity_max: 1.0,
            include_tags: None,
            exclude_tags: Some(vec!["Hash".into()]),
        };
        let matches = vec![
            make_match("A", 0.5, vec!["Hash"]),
            make_match("B", 0.5, vec!["Network"]),
        ];
        let result = filter.apply(matches);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "B");
    }
}
