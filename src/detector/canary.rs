//! Canary (honeypot) file detection
//!
//! Canary files are hidden bait files that no legitimate software should touch.
//! Any access to a canary file is 100% malware - zero false positives.

use std::path::Path;
use std::io::Write;
use tracing::{info, warn};

/// Default canary file names
const CANARY_NAMES: &[&str] = &[
    ".~lock.tmp",
    ".DS_Store.bak",
    "~$document.docx",
    ".thumbs.db",
    "desktop.ini.bak",
];

/// Check if a path is a canary file
pub fn is_canary(path: &Path, prefix: &str) -> bool {
    if let Some(file_name) = path.file_name() {
        let name = file_name.to_string_lossy();

        // Check for prefix match
        if name.starts_with(prefix) {
            return true;
        }

        // Check against known canary names
        for canary_name in CANARY_NAMES {
            if name == *canary_name {
                return true;
            }
        }
    }

    false
}

/// Create canary files in a directory
pub fn create_canaries(dir: &Path, prefix: &str) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut created = Vec::new();

    // Create primary canary with prefix
    let primary = dir.join(format!("{}sentinel", prefix));
    create_canary_file(&primary)?;
    created.push(primary);

    // Create some decoy canaries with common names
    for name in CANARY_NAMES.iter().take(2) {
        let canary_path = dir.join(name);
        if !canary_path.exists() {
            if let Ok(()) = create_canary_file(&canary_path) {
                created.push(canary_path);
            }
        }
    }

    info!("Created {} canary files in {:?}", created.len(), dir);

    Ok(created)
}

/// Create a single canary file
fn create_canary_file(path: &Path) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;

    // Write canary marker (helps identify if file is modified vs deleted)
    let content = format!(
        "SENTINEL_CANARY_V1\n\
         Created: {}\n\
         Path: {}\n\
         DO NOT MODIFY OR DELETE\n",
        chrono::Utc::now().to_rfc3339(),
        path.display()
    );

    file.write_all(content.as_bytes())?;

    // Set file as hidden (on Unix, dot-prefix handles this)
    // Make it read-only to make modification more suspicious
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o444); // Read-only
        std::fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Remove canary files from a directory
pub fn remove_canaries(dir: &Path, prefix: &str) -> std::io::Result<()> {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if is_canary(&path, prefix) {
                // Make writable first (we set it read-only)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(mut perms) = std::fs::metadata(&path).map(|m| m.permissions()) {
                        perms.set_mode(0o644);
                        let _ = std::fs::set_permissions(&path, perms);
                    }
                }

                if let Err(e) = std::fs::remove_file(&path) {
                    warn!("Failed to remove canary {:?}: {}", path, e);
                } else {
                    info!("Removed canary file: {:?}", path);
                }
            }
        }
    }

    Ok(())
}

/// Verify canary files are intact
pub fn verify_canaries(dir: &Path, prefix: &str) -> Vec<CanaryStatus> {
    let mut status = Vec::new();

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if is_canary(&path, prefix) {
                let canary_status = check_canary(&path);
                status.push(canary_status);
            }
        }
    }

    status
}

/// Status of a canary file
#[derive(Debug, Clone)]
pub struct CanaryStatus {
    pub path: std::path::PathBuf,
    pub status: CanaryState,
}

/// State of a canary file
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryState {
    /// Canary is intact
    Intact,
    /// Canary was modified
    Modified,
    /// Canary was deleted
    Deleted,
    /// Error checking canary
    Error(String),
}

/// Check the status of a canary file
fn check_canary(path: &Path) -> CanaryStatus {
    let status = if !path.exists() {
        CanaryState::Deleted
    } else {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                if content.starts_with("SENTINEL_CANARY_V1") {
                    CanaryState::Intact
                } else {
                    CanaryState::Modified
                }
            }
            Err(e) => CanaryState::Error(e.to_string()),
        }
    };

    CanaryStatus {
        path: path.to_path_buf(),
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_is_canary() {
        let prefix = ".sentinel_canary_";

        assert!(is_canary(Path::new("/home/user/.sentinel_canary_test"), prefix));
        assert!(is_canary(Path::new("/home/user/.~lock.tmp"), prefix));
        assert!(!is_canary(Path::new("/home/user/document.pdf"), prefix));
    }

    #[test]
    fn test_create_and_verify_canaries() {
        let dir = tempdir().unwrap();
        let prefix = ".sentinel_canary_";

        // Create canaries
        let created = create_canaries(dir.path(), prefix).unwrap();
        assert!(!created.is_empty());

        // Verify they're intact
        let status = verify_canaries(dir.path(), prefix);
        for s in &status {
            assert_eq!(s.status, CanaryState::Intact);
        }

        // Modify one
        std::fs::write(&created[0], "HACKED!").unwrap();

        // Verify it's detected as modified
        let status = verify_canaries(dir.path(), prefix);
        assert!(status.iter().any(|s| s.status == CanaryState::Modified));
    }
}
