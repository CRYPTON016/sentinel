//! inotify-based file system watcher

use super::{FileEvent, EventType};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use inotify::{Inotify, WatchMask, WatchDescriptor, EventMask};
use tokio::io::unix::AsyncFd;

/// inotify-based file system watcher
pub struct InotifyWatcher {
    /// inotify instance
    inotify: Inotify,
    /// Async wrapper for non-blocking reads
    async_fd: AsyncFd<std::os::unix::io::RawFd>,
    /// Map of watch descriptors to paths
    watches: HashMap<WatchDescriptor, PathBuf>,
    /// Reverse map of paths to watch descriptors
    path_to_wd: HashMap<PathBuf, WatchDescriptor>,
    /// Event buffer
    buffer: [u8; 4096],
}

impl InotifyWatcher {
    /// Create a new inotify watcher
    pub fn new() -> anyhow::Result<Self> {
        let inotify = Inotify::init()?;

        // Get the file descriptor for async operations
        use std::os::unix::io::AsRawFd;
        let fd = inotify.as_raw_fd();

        // Set non-blocking
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let async_fd = AsyncFd::new(fd)?;

        Ok(Self {
            inotify,
            async_fd,
            watches: HashMap::new(),
            path_to_wd: HashMap::new(),
            buffer: [0u8; 4096],
        })
    }

    /// Add a path to watch
    pub fn add(&mut self, path: &Path) -> anyhow::Result<()> {
        // Watch for modifications, creations, deletions
        let mask = WatchMask::MODIFY
            | WatchMask::CREATE
            | WatchMask::DELETE
            | WatchMask::CLOSE_WRITE
            | WatchMask::MOVED_FROM
            | WatchMask::MOVED_TO;

        let wd = self.inotify.watches().add(path, mask)?;

        self.watches.insert(wd.clone(), path.to_path_buf());
        self.path_to_wd.insert(path.to_path_buf(), wd);

        // If it's a directory, also watch subdirectories
        if path.is_dir() {
            self.add_recursive(path)?;
        }

        Ok(())
    }

    /// Recursively add subdirectories
    fn add_recursive(&mut self, dir: &Path) -> anyhow::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Skip common directories that shouldn't be watched
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if [".", "..", ".git", "node_modules", "__pycache__", ".cache", "target"]
                    .contains(&name)
                {
                    continue;
                }

                let mask = WatchMask::MODIFY
                    | WatchMask::CREATE
                    | WatchMask::DELETE
                    | WatchMask::CLOSE_WRITE
                    | WatchMask::MOVED_FROM
                    | WatchMask::MOVED_TO;

                if let Ok(wd) = self.inotify.watches().add(&path, mask) {
                    self.watches.insert(wd.clone(), path.clone());
                    self.path_to_wd.insert(path.clone(), wd);
                }

                // Recurse into subdirectory
                let _ = self.add_recursive(&path);
            }
        }

        Ok(())
    }

    /// Remove a path from watching
    pub fn remove(&mut self, path: &Path) -> anyhow::Result<()> {
        if let Some(wd) = self.path_to_wd.remove(path) {
            self.inotify.watches().remove(wd.clone())?;
            self.watches.remove(&wd);
        }

        Ok(())
    }

    /// Get next event (async)
    pub async fn next_event(&mut self) -> anyhow::Result<Option<FileEvent>> {
        // Wait for the fd to be readable
        loop {
            let mut guard = self.async_fd.readable().await?;

            match self.inotify.read_events(&mut self.buffer) {
                Ok(events) => {
                    for event in events {
                        // Get the directory this event came from
                        let dir_path = match self.watches.get(&event.wd) {
                            Some(p) => p.clone(),
                            None => continue,
                        };

                        // Build full path
                        let file_path = if let Some(name) = event.name {
                            dir_path.join(name)
                        } else {
                            dir_path
                        };

                        // Map event mask to event type
                        let event_type = if event.mask.contains(EventMask::CREATE) {
                            EventType::Create
                        } else if event.mask.contains(EventMask::MODIFY) {
                            EventType::Modify
                        } else if event.mask.contains(EventMask::DELETE) {
                            EventType::Delete
                        } else if event.mask.contains(EventMask::CLOSE_WRITE) {
                            EventType::CloseWrite
                        } else if event.mask.contains(EventMask::MOVED_FROM)
                            || event.mask.contains(EventMask::MOVED_TO)
                        {
                            EventType::Rename
                        } else {
                            continue; // Unknown event type
                        };

                        // If a new directory was created, watch it too
                        if event.mask.contains(EventMask::CREATE)
                            && event.mask.contains(EventMask::ISDIR)
                        {
                            let _ = self.add(&file_path);
                        }

                        return Ok(Some(FileEvent {
                            path: file_path,
                            event_type,
                            pid: None,       // inotify doesn't provide PID
                            process_name: None,
                            fd: None,
                        }));
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Clear readiness and wait again
                    guard.clear_ready();
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}
