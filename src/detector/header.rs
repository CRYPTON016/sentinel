//! File header (magic byte) validation
//!
//! Ransomware encrypts entire files including headers. A .docx that doesn't
//! start with PK (ZIP signature) has been encrypted. This module validates
//! that file headers match their extensions.

use crate::detector::ThreatLevel;
use std::path::Path;

/// Known file signatures (magic bytes)
const SIGNATURES: &[(&[u8], &[&str])] = &[
    // Documents
    (b"PK\x03\x04", &["docx", "xlsx", "pptx", "odt", "ods", "odp", "zip", "jar", "apk"]),
    (b"%PDF", &["pdf"]),
    (b"\xD0\xCF\x11\xE0", &["doc", "xls", "ppt", "msg"]), // OLE2

    // Images
    (b"\x89PNG\r\n\x1A\n", &["png"]),
    (b"\xFF\xD8\xFF", &["jpg", "jpeg"]),
    (b"GIF87a", &["gif"]),
    (b"GIF89a", &["gif"]),
    (b"RIFF", &["webp", "wav", "avi"]),
    (b"BM", &["bmp"]),

    // Audio/Video
    (b"ID3", &["mp3"]),
    (b"\xFF\xFB", &["mp3"]),
    (b"\xFF\xFA", &["mp3"]),
    (b"OggS", &["ogg", "ogv", "oga"]),
    (b"\x1A\x45\xDF\xA3", &["mkv", "webm"]),
    (b"\x00\x00\x00\x1C\x66\x74\x79\x70", &["mp4", "m4a", "m4v", "mov"]),
    (b"\x00\x00\x00\x20\x66\x74\x79\x70", &["mp4"]),
    (b"ftyp", &["mp4", "m4a"]),

    // Archives
    (b"\x1F\x8B", &["gz", "tgz"]),
    (b"BZh", &["bz2"]),
    (b"\xFD7zXZ\x00", &["xz"]),
    (b"7z\xBC\xAF\x27\x1C", &["7z"]),
    (b"Rar!\x1A\x07", &["rar"]),

    // Executables
    (b"\x7FELF", &["elf", "so", "bin"]),
    (b"MZ", &["exe", "dll"]),
    (b"\xCF\xFA\xED\xFE", &["macho"]), // Mach-O 64-bit
    (b"\xCA\xFE\xBA\xBE", &["macho"]), // Mach-O universal

    // Scripts (text-based, just check for shebang or common starts)
    (b"#!", &["sh", "bash", "py", "pl", "rb"]),
    (b"<?xml", &["xml", "svg"]),
    (b"<!DOCTYPE", &["html", "htm"]),
    (b"<html", &["html", "htm"]),

    // Databases
    (b"SQLite format 3", &["sqlite", "db", "sqlite3"]),

    // Fonts
    (b"\x00\x01\x00\x00", &["ttf"]),
    (b"OTTO", &["otf"]),
    (b"wOFF", &["woff"]),
    (b"wOF2", &["woff2"]),
];

/// Validate that a file's header matches its extension
///
/// Returns `Some(ThreatLevel::Critical)` if the header is invalid for the extension,
/// indicating likely encryption. Returns `None` if valid or unknown.
pub fn validate(path: &Path, content: &[u8]) -> Option<ThreatLevel> {
    // Need at least some bytes to check
    if content.len() < 8 {
        return None;
    }

    // Get extension
    let extension = match path.extension() {
        Some(ext) => ext.to_string_lossy().to_lowercase(),
        None => return None, // No extension, can't validate
    };

    // Find expected signatures for this extension
    let expected_sigs: Vec<&[u8]> = SIGNATURES
        .iter()
        .filter(|(_, exts)| exts.iter().any(|e| *e == extension))
        .map(|(sig, _)| *sig)
        .collect();

    // If we don't know this extension, skip
    if expected_sigs.is_empty() {
        return None;
    }

    // Check if content starts with any expected signature
    for sig in &expected_sigs {
        if content.len() >= sig.len() && &content[..sig.len()] == *sig {
            return None; // Valid header
        }
    }

    // Header doesn't match - likely encrypted
    Some(ThreatLevel::Critical)
}

/// Get the file type based on magic bytes
pub fn detect_type(content: &[u8]) -> Option<&'static str> {
    if content.len() < 4 {
        return None;
    }

    for (sig, extensions) in SIGNATURES {
        if content.len() >= sig.len() && &content[..sig.len()] == *sig {
            return extensions.first().copied();
        }
    }

    None
}

/// Check if content looks like encrypted/random data
pub fn looks_encrypted(content: &[u8]) -> bool {
    if content.len() < 16 {
        return false;
    }

    // Check first 16 bytes - encrypted data has no recognizable patterns
    let first_16 = &content[..16];

    // If it starts with any known signature, not encrypted
    for (sig, _) in SIGNATURES {
        if first_16.len() >= sig.len() && &first_16[..sig.len()] == *sig {
            return false;
        }
    }

    // Check for printable ASCII (text files)
    let printable_count = first_16.iter().filter(|&&b| b >= 0x20 && b < 0x7F).count();
    if printable_count > 12 {
        return false; // Probably text
    }

    // Check for null bytes pattern (common in some formats)
    let null_count = first_16.iter().filter(|&&b| b == 0).count();
    if null_count > 8 {
        return false; // Probably structured binary
    }

    true // Looks like random data
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_valid_png() {
        let content = b"\x89PNG\r\n\x1A\n\x00\x00\x00\rIHDR";
        let path = PathBuf::from("test.png");
        assert!(validate(&path, content).is_none());
    }

    #[test]
    fn test_invalid_png_header() {
        let content = b"\xDE\xAD\xBE\xEF\x00\x11\x22\x33"; // Random bytes
        let path = PathBuf::from("test.png");
        assert_eq!(validate(&path, content), Some(ThreatLevel::Critical));
    }

    #[test]
    fn test_valid_pdf() {
        let content = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3";
        let path = PathBuf::from("document.pdf");
        assert!(validate(&path, content).is_none());
    }

    #[test]
    fn test_encrypted_pdf() {
        let content = b"\x7B\x2F\x8A\x3C\x99\x12\xAB\xCD"; // Random bytes
        let path = PathBuf::from("document.pdf");
        assert_eq!(validate(&path, content), Some(ThreatLevel::Critical));
    }

    #[test]
    fn test_unknown_extension() {
        let content = b"\xDE\xAD\xBE\xEF";
        let path = PathBuf::from("file.xyz");
        assert!(validate(&path, content).is_none()); // Unknown, skip
    }

    #[test]
    fn test_detect_type() {
        assert_eq!(detect_type(b"\x89PNG\r\n\x1A\n"), Some("png"));
        assert_eq!(detect_type(b"%PDF-1.4"), Some("pdf"));
        assert_eq!(detect_type(b"PK\x03\x04"), Some("docx"));
        assert_eq!(detect_type(b"\xDE\xAD\xBE\xEF"), None);
    }
}
