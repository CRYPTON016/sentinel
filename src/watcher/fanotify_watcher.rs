//! fanotify-based file system watcher with blocking capability
//!
//! fanotify can intercept file operations BEFORE they complete and
//! allow or deny them. This is critical for stopping ransomware
//! before it encrypts files.

use super::{FileEvent, EventType};
use std::path::{Path, PathBuf};
use std::os::unix::io::{AsRawFd, RawFd, AsFd};
use std::os::fd::AsRawFd as _;
use nix::sys::fanotify::{
    Fanotify, InitFlags, EventFFlags, MarkFlags, MaskFlags,
};
use nix::libc;

/// fanotify-based file system watcher
pub struct FanotifyWatcher {
    /// fanotify file descriptor
    fanotify: Fanotify,
    /// Watched mount points
    watched_mounts: Vec<PathBuf>,
}

impl FanotifyWatcher {
    /// Create a new fanotify watcher
    ///
    /// Requires CAP_SYS_ADMIN capability
    pub fn new() -> anyhow::Result<Self> {
        // Initialize fanotify with permission events
        let fanotify = Fanotify::init(
            InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_CLOEXEC,
            EventFFlags::O_RDONLY | EventFFlags::O_LARGEFILE,
        )?;

        Ok(Self {
            fanotify,
            watched_mounts: Vec::new(),
        })
    }

    /// Add a path to watch
    pub fn add(&mut self, path: &Path) -> anyhow::Result<()> {
        // Watch for permission events (can block) and notification events
        let mask = MaskFlags::FAN_OPEN_PERM       // Permission to open
            | MaskFlags::FAN_CLOSE_WRITE          // File closed after write
            | MaskFlags::FAN_MODIFY;              // File modified

        self.fanotify.mark(
            MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
            mask,
            None, // AT_FDCWD
            Some(path),
        )?;

        self.watched_mounts.push(path.to_path_buf());
        tracing::info!("fanotify watching mount: {:?}", path);

        Ok(())
    }

    /// Remove a path from watching
    pub fn remove(&mut self, path: &Path) -> anyhow::Result<()> {
        let mask = MaskFlags::FAN_OPEN_PERM
            | MaskFlags::FAN_CLOSE_WRITE
            | MaskFlags::FAN_MODIFY;

        self.fanotify.mark(
            MarkFlags::FAN_MARK_REMOVE | MarkFlags::FAN_MARK_MOUNT,
            mask,
            None,
            Some(path),
        )?;

        self.watched_mounts.retain(|p| p != path);

        Ok(())
    }

    /// Get next event
    pub async fn next_event(&mut self) -> anyhow::Result<Option<FileEvent>> {
        // Read events from fanotify
        let events = self.fanotify.read_events()?;

        for event in events {
            // Get the file descriptor from the event
            let fd = match event.fd() {
                Some(f) => f,
                None => continue,
            };

            // Get the file path from /proc/self/fd
            let fd_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
            let path = match std::fs::read_link(&fd_path) {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Get process info
            let pid = event.pid();
            let process_name = get_process_name(pid);

            // Determine event type based on mask
            let mask = event.mask();
            let event_type = if mask.contains(MaskFlags::FAN_OPEN_PERM) {
                EventType::AccessRequest
            } else if mask.contains(MaskFlags::FAN_CLOSE_WRITE) {
                EventType::CloseWrite
            } else if mask.contains(MaskFlags::FAN_MODIFY) {
                EventType::Modify
            } else {
                continue; // Unknown event
            };

            return Ok(Some(FileEvent {
                path,
                event_type,
                pid: Some(pid as u32),
                process_name,
                fd: Some(fd.as_raw_fd()),
            }));
        }

        Ok(None)
    }

    /// Allow a pending operation
    pub fn allow(&self, event: &FileEvent) -> anyhow::Result<()> {
        if let Some(fd) = event.fd {
            // Write FAN_ALLOW response
            let response = libc::fanotify_response {
                fd: fd,
                response: libc::FAN_ALLOW,
            };
            unsafe {
                let res = libc::write(
                    self.fanotify.as_fd().as_raw_fd(),
                    &response as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::fanotify_response>(),
                );
                if res < 0 {
                    return Err(anyhow::anyhow!("Failed to write fanotify response"));
                }
            }
        }
        Ok(())
    }

    /// Deny a pending operation
    pub fn deny(&self, event: &FileEvent) -> anyhow::Result<()> {
        if let Some(fd) = event.fd {
            // Write FAN_DENY response
            let response = libc::fanotify_response {
                fd: fd,
                response: libc::FAN_DENY,
            };
            unsafe {
                let res = libc::write(
                    self.fanotify.as_fd().as_raw_fd(),
                    &response as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::fanotify_response>(),
                );
                if res < 0 {
                    return Err(anyhow::anyhow!("Failed to write fanotify response"));
                }
            }
        }
        Ok(())
    }

    /// Get the raw file descriptor
    pub fn as_raw_fd(&self) -> RawFd {
        self.fanotify.as_fd().as_raw_fd()
    }
}

/// Get process name from PID
fn get_process_name(pid: i32) -> Option<String> {
    let comm_path = format!("/proc/{}/comm", pid);
    std::fs::read_to_string(comm_path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Get process executable path from PID
#[allow(dead_code)]
fn get_process_exe(pid: i32) -> Option<PathBuf> {
    let exe_path = format!("/proc/{}/exe", pid);
    std::fs::read_link(exe_path).ok()
}
