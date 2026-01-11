//! Shannon entropy calculation for ransomware detection
//!
//! Entropy measures the randomness of data. Normal files (text, documents)
//! have low entropy (3-5 bits/byte). Encrypted/compressed files have high
//! entropy (7.9-8.0 bits/byte).
//!
//! Ransomware MUST produce high-entropy output - there's no way around this.
//! If the output had patterns, it wouldn't be encrypted.

/// Calculate Shannon entropy of data
///
/// Returns a value between 0.0 (all same bytes) and 8.0 (perfectly random)
///
/// # Performance
///
/// This implementation is optimized for speed:
/// - Single pass through data
/// - Fixed-size frequency table (256 bytes)
/// - No allocations
///
/// Typical throughput: ~500 MB/s on modern CPU
#[inline]
pub fn calculate(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Count byte frequencies
    let mut frequency = [0u64; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    // Calculate entropy
    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &frequency {
        if count > 0 {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// Calculate entropy of a file
pub fn calculate_file(path: &std::path::Path) -> std::io::Result<f64> {
    let data = std::fs::read(path)?;
    Ok(calculate(&data))
}

/// Check if entropy indicates encryption
#[inline]
pub fn is_high_entropy(entropy: f64, threshold: f64) -> bool {
    entropy > threshold
}

/// Check if entropy indicates normal file
#[inline]
pub fn is_low_entropy(entropy: f64, threshold: f64) -> bool {
    entropy < threshold
}

/// Entropy classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyClass {
    /// Very low entropy (repetitive data)
    VeryLow,
    /// Low entropy (text, source code)
    Low,
    /// Medium entropy (binary, some compression)
    Medium,
    /// High entropy (compressed, encrypted)
    High,
    /// Very high entropy (strongly encrypted, random)
    VeryHigh,
}

/// Classify entropy level
pub fn classify(entropy: f64) -> EntropyClass {
    match entropy {
        e if e < 2.0 => EntropyClass::VeryLow,
        e if e < 5.0 => EntropyClass::Low,
        e if e < 7.0 => EntropyClass::Medium,
        e if e < 7.8 => EntropyClass::High,
        _ => EntropyClass::VeryHigh,
    }
}

/// Get typical entropy ranges for common file types
pub fn typical_entropy(file_type: &str) -> (f64, f64) {
    match file_type.to_lowercase().as_str() {
        // Text files
        "txt" | "md" | "rst" => (3.0, 5.0),
        "json" | "yaml" | "yml" | "toml" | "xml" => (3.5, 5.5),
        "html" | "css" | "js" | "ts" => (4.0, 5.5),
        "rs" | "py" | "go" | "c" | "cpp" | "h" => (4.0, 5.5),

        // Documents
        "pdf" => (6.0, 7.8),
        "docx" | "xlsx" | "pptx" => (7.5, 7.95), // Already compressed

        // Images
        "png" | "jpg" | "jpeg" | "gif" | "webp" => (7.0, 7.95),
        "bmp" | "tiff" => (3.0, 7.0),

        // Archives
        "zip" | "gz" | "xz" | "bz2" | "7z" | "rar" => (7.9, 7.999),

        // Encrypted (legitimate)
        "gpg" | "asc" | "enc" | "qnsqy" => (7.95, 8.0),

        // ML models (already high entropy)
        "safetensors" | "gguf" | "bin" | "pt" | "onnx" => (7.5, 7.99),

        // Unknown
        _ => (0.0, 8.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(calculate(&[]), 0.0);
    }

    #[test]
    fn test_entropy_uniform() {
        // All same byte = 0 entropy
        let data = vec![0u8; 1000];
        assert_eq!(calculate(&data), 0.0);
    }

    #[test]
    fn test_entropy_two_values() {
        // Equal distribution of two values = 1.0 entropy
        let data: Vec<u8> = (0..1000).map(|i| (i % 2) as u8).collect();
        let entropy = calculate(&data);
        assert!((entropy - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_entropy_text() {
        let text = b"Hello, World! This is a test of entropy calculation.";
        let entropy = calculate(text);
        assert!(entropy > 3.0 && entropy < 5.0);
    }

    #[test]
    fn test_entropy_random() {
        // Pseudo-random data should have high entropy
        let data: Vec<u8> = (0..10000).map(|i| ((i * 1103515245 + 12345) % 256) as u8).collect();
        let entropy = calculate(&data);
        assert!(entropy > 7.5);
    }

    #[test]
    fn test_classify() {
        assert_eq!(classify(1.0), EntropyClass::VeryLow);
        assert_eq!(classify(4.0), EntropyClass::Low);
        assert_eq!(classify(6.5), EntropyClass::Medium);
        assert_eq!(classify(7.5), EntropyClass::High);
        assert_eq!(classify(7.95), EntropyClass::VeryHigh);
    }
}
