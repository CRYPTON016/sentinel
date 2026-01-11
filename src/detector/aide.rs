//! AIDE-like file integrity checking
//!
//! Periodic baseline integrity verification to detect changes that
//! real-time monitoring may have missed.

use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use std::io::Read;
use serde::{Serialize, Deserialize};
use tracing::{info, warn, error};

/// File integrity baseline database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDatabase {
    /// Version for compatibility
    pub version: u32,
    /// When baseline was created
    pub created: chrono::DateTime<chrono::Utc>,
    /// When baseline was last updated
    pub updated: chrono::DateTime<chrono::Utc>,
    /// File entries
    pub entries: HashMap<PathBuf, FileEntry>,
}

/// Entry for a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// SHA-256 hash of content
    pub hash: String,
    /// File size in bytes
    pub size: u64,
    /// Last modified time
    pub mtime: i64,
    /// File permissions (Unix mode)
    pub mode: u32,
    /// Owner UID
    pub uid: u32,
    /// Owner GID
    pub gid: u32,
}

/// Result of integrity check
#[derive(Debug, Clone)]
pub struct IntegrityResult {
    /// Files that were added since baseline
    pub added: Vec<PathBuf>,
    /// Files that were modified since baseline
    pub modified: Vec<PathBuf>,
    /// Files that were deleted since baseline
    pub deleted: Vec<PathBuf>,
    /// Files that couldn't be checked
    pub errors: Vec<(PathBuf, String)>,
}

impl BaselineDatabase {
    /// Create a new empty database
    pub fn new() -> Self {
        Self {
            version: 1,
            created: chrono::Utc::now(),
            updated: chrono::Utc::now(),
            entries: HashMap::new(),
        }
    }

    /// Load database from file
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let db: BaselineDatabase = serde_json::from_str(&content)?;
        Ok(db)
    }

    /// Save database to file
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Add or update a file entry
    pub fn add_file(&mut self, path: &Path) -> anyhow::Result<()> {
        let entry = create_file_entry(path)?;
        self.entries.insert(path.to_path_buf(), entry);
        self.updated = chrono::Utc::now();
        Ok(())
    }

    /// Remove a file entry
    pub fn remove_file(&mut self, path: &Path) {
        self.entries.remove(path);
        self.updated = chrono::Utc::now();
    }

    /// Check a file against baseline
    pub fn check_file(&self, path: &Path) -> Option<FileStatus> {
        let current = match create_file_entry(path) {
            Ok(entry) => entry,
            Err(_) => return Some(FileStatus::Error),
        };

        match self.entries.get(path) {
            Some(baseline) => {
                if current.hash != baseline.hash {
                    Some(FileStatus::Modified)
                } else if current.mode != baseline.mode || current.uid != baseline.uid {
                    Some(FileStatus::PermissionsChanged)
                } else {
                    Some(FileStatus::Unchanged)
                }
            }
            None => Some(FileStatus::Added),
        }
    }
}

impl Default for BaselineDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Status of a file compared to baseline
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileStatus {
    Unchanged,
    Modified,
    Added,
    Deleted,
    PermissionsChanged,
    Error,
}

/// Create a file entry from a path
fn create_file_entry(path: &Path) -> anyhow::Result<FileEntry> {
    let metadata = fs::metadata(path)?;

    // Calculate hash
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash = format!("{:x}", hasher.finalize());

    // Get Unix metadata
    #[cfg(unix)]
    let (mode, uid, gid) = {
        use std::os::unix::fs::MetadataExt;
        (metadata.mode(), metadata.uid(), metadata.gid())
    };

    #[cfg(not(unix))]
    let (mode, uid, gid) = (0, 0, 0);

    let mtime = metadata
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    Ok(FileEntry {
        hash,
        size: metadata.len(),
        mtime,
        mode,
        uid,
        gid,
    })
}

/// Create a baseline from paths
pub async fn create_baseline(paths: &[PathBuf]) -> anyhow::Result<()> {
    let mut db = BaselineDatabase::new();
    let mut count = 0;

    for path in paths {
        if path.is_file() {
            if let Err(e) = db.add_file(path) {
                warn!("Failed to add {:?}: {}", path, e);
            } else {
                count += 1;
            }
        } else if path.is_dir() {
            count += add_directory_recursive(&mut db, path)?;
        }
    }

    // Save to default location
    let db_path = PathBuf::from("/var/lib/sentinel/aide.db");
    db.save(&db_path)?;

    info!("Created baseline with {} files at {:?}", count, db_path);

    Ok(())
}

/// Add all files in a directory recursively
fn add_directory_recursive(db: &mut BaselineDatabase, dir: &Path) -> anyhow::Result<usize> {
    let mut count = 0;

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Err(e) = db.add_file(&path) {
                warn!("Failed to add {:?}: {}", path, e);
            } else {
                count += 1;
            }
        } else if path.is_dir() {
            // Skip common directories that shouldn't be tracked
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if ![".", "..", ".git", "node_modules", "__pycache__", ".cache"].contains(&name) {
                count += add_directory_recursive(db, &path)?;
            }
        }
    }

    Ok(count)
}

/// Run integrity check against baseline
pub async fn check(path: Option<&Path>) -> anyhow::Result<()> {
    let db_path = PathBuf::from("/var/lib/sentinel/aide.db");

    if !db_path.exists() {
        error!("No baseline found. Run 'sentinel baseline' first.");
        anyhow::bail!("No baseline database found");
    }

    let db = BaselineDatabase::load(&db_path)?;
    let mut result = IntegrityResult {
        added: Vec::new(),
        modified: Vec::new(),
        deleted: Vec::new(),
        errors: Vec::new(),
    };

    // If specific path provided, check only that
    if let Some(p) = path {
        match db.check_file(p) {
            Some(FileStatus::Modified) => result.modified.push(p.to_path_buf()),
            Some(FileStatus::Added) => result.added.push(p.to_path_buf()),
            Some(FileStatus::Deleted) => result.deleted.push(p.to_path_buf()),
            Some(FileStatus::Error) => result.errors.push((p.to_path_buf(), "Error reading file".to_string())),
            _ => {}
        }
    } else {
        // Check all files in baseline
        for (file_path, _entry) in &db.entries {
            if !file_path.exists() {
                result.deleted.push(file_path.clone());
            } else {
                match db.check_file(file_path) {
                    Some(FileStatus::Modified) | Some(FileStatus::PermissionsChanged) => {
                        result.modified.push(file_path.clone());
                    }
                    Some(FileStatus::Error) => {
                        result.errors.push((file_path.clone(), "Error reading file".to_string()));
                    }
                    _ => {}
                }
            }
        }
    }

    // Print results
    println!("Integrity Check Results");
    println!("═══════════════════════════════════════");

    if result.added.is_empty() && result.modified.is_empty() && result.deleted.is_empty() {
        println!("✓ All files intact");
    } else {
        if !result.modified.is_empty() {
            println!("\n⚠ Modified files ({}):", result.modified.len());
            for p in &result.modified {
                println!("  M {:?}", p);
            }
        }

        if !result.deleted.is_empty() {
            println!("\n✗ Deleted files ({}):", result.deleted.len());
            for p in &result.deleted {
                println!("  D {:?}", p);
            }
        }

        if !result.added.is_empty() {
            println!("\n+ Added files ({}):", result.added.len());
            for p in &result.added {
                println!("  A {:?}", p);
            }
        }
    }

    if !result.errors.is_empty() {
        println!("\n! Errors ({}):", result.errors.len());
        for (p, e) in &result.errors {
            println!("  E {:?}: {}", p, e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_baseline_create_and_check() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");

        // Create a test file
        fs::write(&file_path, "Hello, World!").unwrap();

        // Create baseline
        let mut db = BaselineDatabase::new();
        db.add_file(&file_path).unwrap();

        // Check - should be unchanged
        assert_eq!(db.check_file(&file_path), Some(FileStatus::Unchanged));

        // Modify file
        fs::write(&file_path, "Modified!").unwrap();

        // Check - should be modified
        assert_eq!(db.check_file(&file_path), Some(FileStatus::Modified));
    }

    #[test]
    fn test_baseline_save_load() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let file_path = dir.path().join("test.txt");

        fs::write(&file_path, "Test content").unwrap();

        let mut db = BaselineDatabase::new();
        db.add_file(&file_path).unwrap();
        db.save(&db_path).unwrap();

        let loaded = BaselineDatabase::load(&db_path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert!(loaded.entries.contains_key(&file_path));
    }
}
