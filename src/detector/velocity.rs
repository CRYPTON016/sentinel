//! Velocity tracking for mass encryption detection
//!
//! Normal users save 1-2 files per minute. Ransomware encrypts 100+ files per minute.
//! This module tracks high-entropy writes per process and flags excessive rates.

use crate::detector::ThreatLevel;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Tracks write velocity per process
pub struct VelocityTracker {
    /// Maximum high-entropy writes per minute before triggering
    limit: u32,
    /// Window duration for rate limiting
    window: Duration,
    /// Per-process tracking data
    processes: HashMap<u32, ProcessStats>,
}

/// Statistics for a single process
struct ProcessStats {
    /// Count of high-entropy writes in current window
    high_entropy_writes: u32,
    /// When the current window started
    window_start: Instant,
    /// Total writes (for statistics)
    total_writes: u64,
}

impl VelocityTracker {
    /// Create a new velocity tracker
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            window: Duration::from_secs(60),
            processes: HashMap::new(),
        }
    }

    /// Create with custom window duration
    pub fn with_window(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            processes: HashMap::new(),
        }
    }

    /// Check current velocity for a process
    pub fn check(&mut self, pid: u32) -> ThreatLevel {
        let stats = self.processes.entry(pid).or_insert_with(|| ProcessStats {
            high_entropy_writes: 0,
            window_start: Instant::now(),
            total_writes: 0,
        });

        // Reset window if expired
        if stats.window_start.elapsed() > self.window {
            stats.high_entropy_writes = 0;
            stats.window_start = Instant::now();
        }

        // Check if limit exceeded
        if stats.high_entropy_writes >= self.limit {
            ThreatLevel::Critical
        } else if stats.high_entropy_writes >= self.limit / 2 {
            ThreatLevel::Suspicious
        } else {
            ThreatLevel::Safe
        }
    }

    /// Record a high-entropy write for a process
    pub fn record_high_entropy(&mut self, pid: u32) {
        let stats = self.processes.entry(pid).or_insert_with(|| ProcessStats {
            high_entropy_writes: 0,
            window_start: Instant::now(),
            total_writes: 0,
        });

        // Reset window if expired
        if stats.window_start.elapsed() > self.window {
            stats.high_entropy_writes = 0;
            stats.window_start = Instant::now();
        }

        stats.high_entropy_writes += 1;
        stats.total_writes += 1;
    }

    /// Record any write for a process (for statistics)
    pub fn record_write(&mut self, pid: u32) {
        let stats = self.processes.entry(pid).or_insert_with(|| ProcessStats {
            high_entropy_writes: 0,
            window_start: Instant::now(),
            total_writes: 0,
        });

        stats.total_writes += 1;
    }

    /// Get current count for a process
    pub fn get_count(&self, pid: u32) -> u32 {
        self.processes
            .get(&pid)
            .map(|s| s.high_entropy_writes)
            .unwrap_or(0)
    }

    /// Get total writes for a process
    pub fn get_total_writes(&self, pid: u32) -> u64 {
        self.processes
            .get(&pid)
            .map(|s| s.total_writes)
            .unwrap_or(0)
    }

    /// Clear statistics for a process (e.g., when process exits)
    pub fn clear(&mut self, pid: u32) {
        self.processes.remove(&pid);
    }

    /// Clear all stale entries (processes with old windows)
    pub fn cleanup(&mut self) {
        let stale_threshold = self.window * 5;
        self.processes.retain(|_, stats| {
            stats.window_start.elapsed() < stale_threshold
        });
    }

    /// Get all processes currently being tracked
    pub fn tracked_processes(&self) -> Vec<(u32, u32)> {
        self.processes
            .iter()
            .map(|(pid, stats)| (*pid, stats.high_entropy_writes))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_velocity_under_limit() {
        let mut tracker = VelocityTracker::new(10);

        for _ in 0..5 {
            tracker.record_high_entropy(1234);
        }

        assert_eq!(tracker.check(1234), ThreatLevel::Suspicious); // 5 = half of 10
    }

    #[test]
    fn test_velocity_at_limit() {
        let mut tracker = VelocityTracker::new(10);

        for _ in 0..10 {
            tracker.record_high_entropy(1234);
        }

        assert_eq!(tracker.check(1234), ThreatLevel::Critical);
    }

    #[test]
    fn test_velocity_different_processes() {
        let mut tracker = VelocityTracker::new(10);

        for _ in 0..5 {
            tracker.record_high_entropy(1234);
            tracker.record_high_entropy(5678);
        }

        // Each process has 5 writes, not 10
        assert_eq!(tracker.check(1234), ThreatLevel::Suspicious);
        assert_eq!(tracker.check(5678), ThreatLevel::Suspicious);
    }

    #[test]
    fn test_window_reset() {
        let mut tracker = VelocityTracker::with_window(10, Duration::from_millis(100));

        for _ in 0..10 {
            tracker.record_high_entropy(1234);
        }
        assert_eq!(tracker.check(1234), ThreatLevel::Critical);

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(150));

        // Window should reset, back to safe
        assert_eq!(tracker.check(1234), ThreatLevel::Safe);
    }
}
