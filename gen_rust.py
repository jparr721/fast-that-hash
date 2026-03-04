#!/usr/bin/env python3
"""Read hashes.py and emit the Rust source for src/hashes.rs"""

import sys
import os

# Import the prototypes directly
sys.path.insert(0, os.path.dirname(__file__))
from hashes import prototypes


def rust_opt_u32(val):
    if val is None:
        return "None"
    # Some hashcat values are strings (yescrypt has a string note)
    if isinstance(val, str):
        return "None"
    return f"Some({val})"


def rust_opt_str(val):
    if val is None:
        return "None"
    # Escape backslashes and quotes for Rust string literals
    escaped = val.replace("\\", "\\\\").replace('"', '\\"')
    return f'Some("{escaped}")'


def rust_bool(val):
    return "true" if val else "false"


def rust_str(val):
    return f'"{val}"'


def pattern_to_rust(regex_obj):
    """Convert a compiled Python regex to a Rust pattern string."""
    import re as _re
    pattern = regex_obj.pattern
    flags = regex_obj.flags

    # Rust regex treats { as repetition start unless escaped.
    # We need to escape literal { and } that aren't part of {n}, {n,}, {n,m}.
    # Strategy: find all { that ARE valid quantifiers and leave them, escape the rest.
    def escape_braces(pat):
        result = []
        i = 0
        while i < len(pat):
            if pat[i] == '{':
                # Check if this is a valid quantifier: {digits} or {digits,} or {digits,digits}
                match = _re.match(r'\{(\d+)(,\d*)?\}', pat[i:])
                if match:
                    result.append(match.group(0))
                    i += len(match.group(0))
                    continue
                else:
                    result.append('\\{')
                    i += 1
                    continue
            elif pat[i] == '}':
                result.append('\\}')
                i += 1
                continue
            elif pat[i] == '\\' and i + 1 < len(pat):
                # Already escaped — pass through the pair
                result.append(pat[i:i+2])
                i += 2
                continue
            elif pat[i] == '[':
                # Inside a character class, braces are literal — but Rust handles this fine
                # Find the end of the char class
                j = i + 1
                if j < len(pat) and pat[j] == '^':
                    j += 1
                if j < len(pat) and pat[j] == ']':
                    j += 1
                while j < len(pat) and pat[j] != ']':
                    if pat[j] == '\\':
                        j += 1
                    j += 1
                j += 1  # skip closing ]
                result.append(pat[i:j])
                i = j
                continue
            else:
                result.append(pat[i])
                i += 1
        return ''.join(result)

    pattern = escape_braces(pattern)

    case_insensitive = bool(flags & _re.IGNORECASE)
    if case_insensitive:
        if not pattern.startswith("(?i)"):
            pattern = "(?i)" + pattern

    return pattern


def main():
    lines = []
    lines.append('//! Hash identification prototypes — auto-generated from hashes.py')
    lines.append('use std::sync::LazyLock;')
    lines.append('use regex::RegexSet;')
    lines.append('')
    lines.append('pub struct HashInfo {')
    lines.append('    pub name: &\'static str,')
    lines.append('    pub hashcat: Option<u32>,')
    lines.append('    pub john: Option<&\'static str>,')
    lines.append('    pub extended: bool,')
    lines.append('    pub description: Option<&\'static str>,')
    lines.append('}')
    lines.append('')
    lines.append('pub struct Prototype {')
    lines.append('    pub regex_index: usize,')
    lines.append('    pub modes: &\'static [HashInfo],')
    lines.append('}')
    lines.append('')

    # Collect patterns
    patterns = []
    for i, proto in enumerate(prototypes):
        pat = pattern_to_rust(proto.regex)
        patterns.append(pat)

    # Emit PATTERNS array
    lines.append(f'static PATTERNS: &[&str] = &[')
    for pat in patterns:
        # Use a raw string in Rust to avoid double-escaping
        # But raw strings can't contain unbalanced # so use regular strings
        # and escape backslashes
        escaped = pat.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    "{escaped}",')
    lines.append('];')
    lines.append('')

    # Emit PROTOTYPES array
    lines.append('static PROTOTYPES: &[Prototype] = &[')
    for i, proto in enumerate(prototypes):
        lines.append(f'    Prototype {{')
        lines.append(f'        regex_index: {i},')
        lines.append(f'        modes: &[')
        for mode in proto.modes:
            name_escaped = mode.name.replace("\\", "\\\\").replace('"', '\\"')
            desc = rust_opt_str(mode.description) if mode.description else "None"
            lines.append(f'            HashInfo {{')
            lines.append(f'                name: "{name_escaped}",')
            lines.append(f'                hashcat: {rust_opt_u32(mode.hashcat)},')
            lines.append(f'                john: {rust_opt_str(mode.john)},')
            lines.append(f'                extended: {rust_bool(mode.extended)},')
            lines.append(f'                description: {desc},')
            lines.append(f'            }},')
        lines.append(f'        ],')
        lines.append(f'    }},')
    lines.append('];')
    lines.append('')

    # Emit RegexSet and identify function
    lines.append('pub static REGEX_SET: LazyLock<RegexSet> = LazyLock::new(|| {')
    lines.append('    regex::RegexSetBuilder::new(PATTERNS)')
    lines.append('        .size_limit(64 * 1024 * 1024)')
    lines.append('        .build()')
    lines.append('        .unwrap()')
    lines.append('});')
    lines.append('')
    lines.append("/// Identify a hash string, returning all matching HashInfo entries.")
    lines.append("pub fn identify(hash: &str) -> Vec<&'static HashInfo> {")
    lines.append('    let matches = REGEX_SET.matches(hash);')
    lines.append('    let mut results = Vec::new();')
    lines.append('    for proto in PROTOTYPES.iter() {')
    lines.append('        if matches.matched(proto.regex_index) {')
    lines.append('            results.extend(proto.modes.iter());')
    lines.append('        }')
    lines.append('    }')
    lines.append('    results')
    lines.append('}')
    lines.append('')

    output = "\n".join(lines)
    with open("src/hashes.rs", "w") as f:
        f.write(output)

    print(f"Generated src/hashes.rs with {len(prototypes)} prototypes and {len(patterns)} patterns", file=sys.stderr)


if __name__ == "__main__":
    main()
