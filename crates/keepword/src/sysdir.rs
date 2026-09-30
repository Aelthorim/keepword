//! Finding the node's data directory, and running as the user that owns it.
//!
//! On an installed node the data belongs to the `keepword` service user. So
//! that `keepword …` just works from a root shell or with sudo, the CLI
//! finds the installed node on its own and, when started as root, switches
//! to the owner of the data directory before touching anything. Files it
//! creates then belong to the service, as they must.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// Where the installer records a non-default data directory.
pub const SYSTEM_DIR_FILE: &str = "/etc/keepword/data-dir";
/// The installer's default data directory.
pub const SYSTEM_DIR: &str = "/var/lib/keepword";
/// A development node in the current directory.
pub const LOCAL_DIR: &str = "./keepword-data";

/// The data directory to use: the one given (`--dir` or `KEEPWORD_DIR`),
/// else `./keepword-data` if it exists, else the installed node's, else
/// `./keepword-data`.
pub fn resolve(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(d) = explicit {
        return d;
    }
    let local = PathBuf::from(LOCAL_DIR);
    if local.exists() {
        return local;
    }
    if let Ok(s) = fs::read_to_string(SYSTEM_DIR_FILE) {
        let s = s.trim();
        if !s.is_empty() {
            return PathBuf::from(s);
        }
    }
    // A directory is enough: other users can't look inside it.
    let system = Path::new(SYSTEM_DIR);
    if system.is_dir() {
        return system.to_path_buf();
    }
    local
}

/// If running as root and `dir` belongs to another user, become that user.
/// Otherwise, if `dir` can't be read, explain how to get access. Call this
/// before any other threads start.
#[cfg(unix)]
pub fn become_owner(dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: plain libc calls without pointers, apart from the null group
    // list that setgroups(0, ...) is documented to accept.
    if unsafe { libc::geteuid() } != 0 {
        return match fs::read_dir(dir) {
            Err(e) if e.kind() == ErrorKind::PermissionDenied => bail!(
                "{} belongs to the keepword service; run this command as root or with sudo \
                 (it switches to the service user by itself)",
                dir.display()
            ),
            _ => Ok(()),
        };
    }
    let Ok(meta) = fs::metadata(dir) else {
        return Ok(());
    };
    let (uid, gid) = (meta.uid(), meta.gid());
    if uid == 0 {
        return Ok(());
    }
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setgid(gid) != 0
            || libc::setuid(uid) != 0
        {
            bail!(
                "could not switch to the owner of {} (uid {uid}): {}",
                dir.display(),
                std::io::Error::last_os_error()
            );
        }
        // Root must be gone for good, not just set aside.
        if libc::setuid(0) == 0 || libc::geteuid() != uid || libc::getegid() != gid {
            bail!("dropping root privileges failed");
        }
        // SAFETY: called before the runtime or any other thread starts.
        std::env::set_var("HOME", dir);
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn become_owner(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_dir_wins() {
        let d = PathBuf::from("/somewhere/else");
        assert_eq!(resolve(Some(d.clone())), d);
    }
}
