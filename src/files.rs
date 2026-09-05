use crate::cli::FileMask;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn wildcard_matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut pattern_index, mut name_index) = (0, 0);
    let (mut star, mut after_star) = (None, 0);
    while name_index < name.len() {
        if pattern.get(pattern_index) == Some(&'?')
            || pattern.get(pattern_index) == name.get(name_index)
        {
            pattern_index += 1;
            name_index += 1;
        } else if pattern.get(pattern_index) == Some(&'*') {
            star = Some(pattern_index);
            pattern_index += 1;
            after_star = name_index;
        } else if let Some(star_index) = star {
            pattern_index = star_index + 1;
            after_star += 1;
            name_index = after_star;
        } else {
            return false;
        }
    }
    while pattern.get(pattern_index) == Some(&'*') {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn walk(
    directory: &Path,
    pattern: &str,
    recursive: bool,
    output: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "Cannot read directory {}: {error}",
                directory.display()
            ));
        }
    };
    let mut entries = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Cannot read directory {}: {error}", directory.display()))?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut children = Vec::new();
    for entry in entries {
        let file_type = entry
            .file_type()
            .map_err(|error| format!("Cannot inspect file {}: {error}", entry.path().display()))?;
        if file_type.is_file()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| wildcard_matches(pattern, name))
        {
            output.push(entry.path());
        }
        if recursive && file_type.is_dir() && !file_type.is_symlink() {
            children.push(entry.path());
        }
    }
    for child in children {
        walk(&child, pattern, true, output)?;
    }
    Ok(())
}

pub fn expand(masks: &[FileMask]) -> Result<Vec<PathBuf>, String> {
    let mut output = Vec::new();
    for mask in masks {
        if !mask.pattern.contains(['*', '?']) {
            output.push(PathBuf::from(&mask.pattern));
            continue;
        }
        let path = Path::new(&mask.pattern);
        let directory = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let pattern = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or("The wildcard file name is not valid UTF-8.")?;
        walk(directory, pattern, mask.recursive, &mut output)?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_wildcards_and_recursion() {
        let root = std::env::temp_dir().join(format!("hview-file-tests-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("child")).unwrap();
        for name in ["root.bin", "ROOT.TXT", "no_extension", "child/nested.bin"] {
            let path = root.join(name);
            std::fs::write(path, b"fixture").unwrap();
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&root, root.join("child/cycle")).unwrap();
        let mask = |name: &str, recursive| FileMask {
            pattern: root.join(name).to_string_lossy().into_owned(),
            recursive,
            remaining_args: 1,
        };
        assert_eq!(
            expand(&[mask("*.bin", false)]).unwrap(),
            [root.join("root.bin")]
        );
        assert_eq!(
            expand(&[mask("*.bin", true)]).unwrap(),
            [root.join("root.bin"), root.join("child/nested.bin")]
        );
        assert!(expand(&[mask("*.BIN", true)]).unwrap().is_empty());
        assert_eq!(
            expand(&[mask("missing.bin", true)]).unwrap(),
            [root.join("missing.bin")]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wildcard_matching_handles_stars_and_questions() {
        assert!(wildcard_matches("a*.?in", "alpha.bin"));
        assert!(wildcard_matches("*", ""));
        assert!(!wildcard_matches("a?", "a"));
    }
}
