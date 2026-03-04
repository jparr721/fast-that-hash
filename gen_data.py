#!/usr/bin/env python3
"""Generate Rust source files from JSON data in Data/"""

import json
import sys


def escape_rust_str(s):
    """Escape a string for use in a Rust string literal."""
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\t", "\\t")
    return s


def escape_regex_braces(pat):
    """Escape literal { and } that aren't part of regex quantifiers like {n}, {n,}, {n,m}."""
    import re as _re

    result = []
    i = 0
    while i < len(pat):
        if pat[i] == "{":
            # Check if this is a valid quantifier: {digits} or {digits,} or {digits,digits}
            match = _re.match(r"\{(\d+)(,\d*)?\}", pat[i:])
            if match:
                result.append(match.group(0))
                i += len(match.group(0))
                continue
            else:
                result.append("\\{")
                i += 1
                continue
        elif pat[i] == "}":
            result.append("\\}")
            i += 1
            continue
        elif pat[i] == "\\" and i + 1 < len(pat):
            # Already escaped — pass through the pair
            result.append(pat[i : i + 2])
            i += 2
            continue
        elif pat[i] == "[":
            # Inside a character class — find the end
            j = i + 1
            if j < len(pat) and pat[j] == "^":
                j += 1
            if j < len(pat) and pat[j] == "]":
                j += 1
            while j < len(pat) and pat[j] != "]":
                if pat[j] == "\\":
                    j += 1
                j += 1
            j += 1
            result.append(pat[i:j])
            i = j
            continue
        else:
            result.append(pat[i])
            i += 1
    return "".join(result)


def rust_opt_str(val):
    if val is None:
        return "None"
    return f'Some("{escape_rust_str(str(val))}")'


def rust_bool(val):
    return "true" if val else "false"


def write_file(path, lines):
    with open(path, "w") as f:
        f.write("\n".join(lines))


def gen_mac_vendors():
    with open("Data/mac_vendors.json") as f:
        data = json.load(f)
    entries = sorted(data.items(), key=lambda x: x[0].upper())

    lines = [
        "//! MAC vendor lookup — auto-generated from mac_vendors.json",
        "",
        "pub struct MacVendor {",
        "    pub prefix: &'static str,",
        "    pub vendor: &'static str,",
        "}",
        "",
        "static MAC_VENDORS: &[MacVendor] = &[",
    ]
    for prefix, vendor in entries:
        p = escape_rust_str(prefix.upper())
        v = escape_rust_str(vendor)
        lines.append(f'    MacVendor {{ prefix: "{p}", vendor: "{v}" }},')
    lines.extend(
        [
            "];",
            "",
            "/// Look up a MAC vendor by prefix (binary search on sorted array).",
            "/// Tries 9, 7, and 6 character OUI prefix lengths.",
            "pub fn lookup_mac_vendor(mac: &str) -> Option<&'static str> {",
            "    let normalized: String = mac.chars()",
            "        .filter(|c| c.is_ascii_hexdigit())",
            "        .flat_map(|c| c.to_uppercase())",
            "        .collect();",
            "    for len in [9, 7, 6] {",
            "        if normalized.len() >= len {",
            "            let prefix = &normalized[..len];",
            "            if let Ok(i) = MAC_VENDORS.binary_search_by_key(&prefix, |e| e.prefix) {",
            "                return Some(MAC_VENDORS[i].vendor);",
            "            }",
            "        }",
            "    }",
            "    None",
            "}",
            "",
        ]
    )

    write_file("src/mac_vendors.rs", lines)
    print(
        f"Generated src/mac_vendors.rs with {len(entries)} entries", file=sys.stderr
    )


def gen_mastercard():
    with open("Data/mastercard_companies.json") as f:
        data = json.load(f)
    entries = sorted(data.items())

    lines = [
        "//! Mastercard BIN lookup — auto-generated from mastercard_companies.json",
        "",
        "pub struct MastercardBin {",
        "    pub bin: &'static str,",
        "    pub company: &'static str,",
        "}",
        "",
        "static MASTERCARD_BINS: &[MastercardBin] = &[",
    ]
    for bin_num, company in entries:
        b = escape_rust_str(bin_num)
        c = escape_rust_str(company)
        lines.append(f'    MastercardBin {{ bin: "{b}", company: "{c}" }},')
    lines.extend(
        [
            "];",
            "",
            "/// Look up a Mastercard company by BIN prefix (binary search).",
            "pub fn lookup_mastercard(bin: &str) -> Option<&'static str> {",
            "    let prefix = if bin.len() >= 6 { &bin[..6] } else { bin };",
            "    MASTERCARD_BINS",
            "        .binary_search_by_key(&prefix, |e| e.bin)",
            "        .ok()",
            "        .map(|i| MASTERCARD_BINS[i].company)",
            "}",
            "",
        ]
    )

    write_file("src/mastercard.rs", lines)
    print(
        f"Generated src/mastercard.rs with {len(entries)} entries", file=sys.stderr
    )


def gen_phone_codes():
    with open("Data/phone_codes.json") as f:
        data = json.load(f)
    entries = sorted(data.items())

    lines = [
        "//! Phone country code lookup — auto-generated from phone_codes.json",
        "",
        "pub struct PhoneCode {",
        "    pub code: &'static str,",
        "    pub country: &'static str,",
        "}",
        "",
        "static PHONE_CODES: &[PhoneCode] = &[",
    ]
    for code, country in entries:
        c = escape_rust_str(code)
        co = escape_rust_str(country)
        lines.append(f'    PhoneCode {{ code: "{c}", country: "{co}" }},')
    lines.extend(
        [
            "];",
            "",
            "/// Look up a country by phone code (binary search).",
            "pub fn lookup_phone_code(code: &str) -> Option<&'static str> {",
            "    PHONE_CODES",
            "        .binary_search_by_key(&code, |e| e.code)",
            "        .ok()",
            "        .map(|i| PHONE_CODES[i].country)",
            "}",
            "",
        ]
    )

    write_file("src/phone_codes.rs", lines)
    print(
        f"Generated src/phone_codes.rs with {len(entries)} entries", file=sys.stderr
    )


def gen_file_signatures():
    with open("Data/file_signatures.json") as f:
        data = json.load(f)

    lines = [
        "//! File signature identification — auto-generated from file_signatures.json",
        "",
        "pub struct FileSignature {",
        "    pub sig_hex: &'static str,",
        "    pub iso: Option<&'static str>,",
        "    pub url: Option<&'static str>,",
        "    pub extension: Option<&'static str>,",
        "    pub desc: &'static str,",
        "    pub popular: bool,",
        "}",
        "",
        "pub static FILE_SIGNATURES: &[FileSignature] = &[",
    ]
    for entry in data:
        sig = escape_rust_str(entry.get("Hexadecimal File Signature", ""))
        iso = rust_opt_str(entry.get("ISO 8859-1"))
        url = rust_opt_str(entry.get("URL"))
        ext = rust_opt_str(entry.get("Filename Extension"))
        desc = escape_rust_str(entry.get("Description", ""))
        popular = rust_bool(entry.get("Popular", 0))
        lines.extend(
            [
                "    FileSignature {",
                f'        sig_hex: "{sig}",',
                f"        iso: {iso},",
                f"        url: {url},",
                f"        extension: {ext},",
                f'        desc: "{desc}",',
                f"        popular: {popular},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "/// Identify a file by its hex signature prefix.",
            "pub fn identify_file(hex_bytes: &str) -> Vec<&'static FileSignature> {",
            "    let lower = hex_bytes.to_lowercase();",
            "    FILE_SIGNATURES",
            "        .iter()",
            "        .filter(|sig| lower.starts_with(&sig.sig_hex.to_lowercase()))",
            "        .collect()",
            "}",
            "",
        ]
    )

    write_file("src/file_signatures.rs", lines)
    print(
        f"Generated src/file_signatures.rs with {len(data)} entries", file=sys.stderr
    )


def gen_regex_patterns():
    with open("Data/regex.json") as f:
        data = json.load(f)

    valid_entries = [e for e in data if e.get("Regex")]

    lines = [
        "//! Regex-based pattern identification — auto-generated from regex.json",
        "use std::sync::LazyLock;",
        "use regex::RegexSet;",
        "",
        "pub struct RegexPattern {",
        "    pub name: &'static str,",
        "    pub plural_name: bool,",
        "    pub description: Option<&'static str>,",
        "    pub rarity: f64,",
        "    pub url: Option<&'static str>,",
        "    pub tags: &'static [&'static str],",
        "    pub regex_index: usize,",
        "}",
        "",
        "static PATTERNS: &[&str] = &[",
    ]
    for entry in valid_entries:
        pat = escape_regex_braces(entry["Regex"])
        pat = escape_rust_str(pat)
        lines.append(f'    "{pat}",')
    lines.extend(
        [
            "];",
            "",
            "static REGEX_PATTERNS: &[RegexPattern] = &[",
        ]
    )
    for i, entry in enumerate(valid_entries):
        name = escape_rust_str(entry.get("Name", ""))
        plural = rust_bool(entry.get("plural_name", False))
        desc = rust_opt_str(entry.get("Description"))
        rarity_val = entry.get("Rarity", 0)
        rarity = f"{float(rarity_val if rarity_val is not None else 0)}"
        url = rust_opt_str(entry.get("URL"))
        tags = entry.get("Tags", [])
        tags_str = ", ".join(f'"{escape_rust_str(t)}"' for t in tags)
        lines.extend(
            [
                "    RegexPattern {",
                f'        name: "{name}",',
                f"        plural_name: {plural},",
                f"        description: {desc},",
                f"        rarity: {rarity}_f64,",
                f"        url: {url},",
                f"        tags: &[{tags_str}],",
                f"        regex_index: {i},",
                "    },",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "pub static REGEX_SET: LazyLock<RegexSet> = LazyLock::new(|| {",
            "    regex::RegexSetBuilder::new(PATTERNS)",
            "        .size_limit(64 * 1024 * 1024)",
            "        .build()",
            "        .unwrap()",
            "});",
            "",
            "/// Identify a string using regex patterns, returning all matches.",
            "pub fn identify_pattern(input: &str) -> Vec<&'static RegexPattern> {",
            "    let matches = REGEX_SET.matches(input);",
            "    REGEX_PATTERNS",
            "        .iter()",
            "        .filter(|p| matches.matched(p.regex_index))",
            "        .collect()",
            "}",
            "",
        ]
    )

    write_file("src/regex_patterns.rs", lines)
    print(
        f"Generated src/regex_patterns.rs with {len(valid_entries)} patterns",
        file=sys.stderr,
    )


def main():
    gen_mac_vendors()
    gen_mastercard()
    gen_phone_codes()
    gen_file_signatures()
    gen_regex_patterns()


if __name__ == "__main__":
    main()
