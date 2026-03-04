use std::path::Path;
use walkdir::WalkDir;

/// Resolve input to a list of strings to identify.
///
/// If `only_text` is true, always treat `input` as raw text regardless of
/// whether it happens to match a path on the filesystem. Otherwise, check
/// whether `input` points to a file or directory and read contents from it;
/// if neither, treat it as raw text.
///
/// # Examples
///
/// ```no_run
/// use fast_that_hash::input::resolve_input;
///
/// // Raw text — returned as-is
/// let items = resolve_input("5f4dcc3b5aa765d61d8327deb882cf99", false);
/// assert_eq!(items, vec!["5f4dcc3b5aa765d61d8327deb882cf99"]);
///
/// // Force text mode even when a path exists
/// let items = resolve_input("/etc/passwd", true);
/// assert_eq!(items, vec!["/etc/passwd"]);
/// ```
pub fn resolve_input(input: &str, only_text: bool) -> Vec<String> {
    if only_text {
        return vec![input.to_string()];
    }

    let path = Path::new(input);

    if path.is_dir() {
        resolve_directory(path)
    } else if path.is_file() {
        resolve_file(path)
    } else {
        vec![input.to_string()]
    }
}

/// Read every non-empty, trimmed line from `path`.
///
/// Returns an empty `Vec` and emits a warning log if the file cannot be read.
fn resolve_file(path: &Path) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => contents
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        Err(e) => {
            log::warn!("Failed to read {}: {}", path.display(), e);
            vec![]
        }
    }
}

/// Recursively walk `path` and collect non-empty lines from every file found.
fn resolve_directory(path: &Path) -> Vec<String> {
    let mut lines = Vec::new();
    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            lines.extend(resolve_file(entry.path()));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_resolve_raw_text() {
        let items = resolve_input("hello world", false);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], "hello world");
    }

    #[test]
    fn test_resolve_only_text() {
        let items = resolve_input("/etc/passwd", true);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], "/etc/passwd");
    }

    #[test]
    fn test_resolve_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "line1").unwrap();
        writeln!(f, "line2").unwrap();
        writeln!(f, "").unwrap();

        let items = resolve_input(path.to_str().unwrap(), false);
        assert_eq!(items, vec!["line1", "line2"]);
    }

    #[test]
    fn test_resolve_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("a.txt");
        let file2 = dir.path().join("b.txt");
        std::fs::write(&file1, "alpha\n").unwrap();
        std::fs::write(&file2, "beta\n").unwrap();

        let items = resolve_input(dir.path().to_str().unwrap(), false);
        assert!(items.contains(&"alpha".to_string()));
        assert!(items.contains(&"beta".to_string()));
    }
}
