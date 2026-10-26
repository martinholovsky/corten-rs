//! `DirCap`: filesystem access only beneath a granted directory
//! (`docs/pathseg.md` section 2).
//!
//! On Linux every open is one `openat2` call with `RESOLVE_BENEATH`,
//! `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS` and `RESOLVE_NO_XDEV`. On
//! every other target, and on a Linux kernel without `openat2`, every
//! operation returns [`FsError::Unsupported`]: there is no weaker fallback.

use std::fmt;
use std::io;

use crate::path::{PathSeg, RelPath};

/// Why a filesystem operation failed.
#[derive(Debug)]
pub enum FsError {
    /// This target cannot resolve paths race-free beneath a directory, so
    /// the monitor refuses (fail closed).
    Unsupported,
    /// A read would exceed the caller's byte budget.
    BudgetExceeded {
        /// The budget the caller gave.
        limit: usize,
    },
    /// The operating system refused, for example `ELOOP` for a symbolic
    /// link or `EXDEV` for an escape or a mount crossing.
    Os(io::Error),
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str(
                "this platform cannot confine opens to a directory (openat2 unavailable); refused",
            ),
            Self::BudgetExceeded { limit } => write!(f, "read exceeds the budget of {limit} bytes"),
            Self::Os(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Os(e) => Some(e),
            _ => None,
        }
    }
}

/// How [`DirCap::open_file`] opens a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Read an existing file.
    Read,
    /// Create a new file; fails if the name exists (no truncation of
    /// something already there, no following a planted link).
    CreateExclusive,
    /// Append to an existing file.
    Append,
}

/// An open directory: the authority to open names beneath it.
///
/// A `DirCap` comes only from a verified capability manifest
/// ([`crate::manifest`]) or from [`DirCap::open_dir`] on another `DirCap`.
#[derive(Debug)]
pub struct DirCap {
    #[cfg(target_os = "linux")]
    fd: rustix::fd::OwnedFd,
}

/// An open file obtained through a [`DirCap`].
#[derive(Debug)]
pub struct CapFile {
    #[cfg(target_os = "linux")]
    fd: rustix::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{CapFile, DirCap, FsError, OpenMode};
    use crate::path::{PathSeg, RelPath};
    use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags};
    use rustix::io::Errno;

    pub(super) const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::NO_MAGICLINKS)
        .union(ResolveFlags::NO_XDEV);

    fn map(e: Errno) -> FsError {
        if e == Errno::NOSYS {
            FsError::Unsupported
        } else {
            FsError::Os(e.into())
        }
    }

    pub(super) fn open_root(path: &std::path::Path) -> Result<DirCap, FsError> {
        let fd = rustix::fs::open(
            path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map)?;
        let dir = DirCap { fd };
        // Probe once: a kernel without openat2 refuses here, not later.
        rustix::fs::openat2(
            &dir.fd,
            ".",
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            RESOLVE,
        )
        .map_err(map)?;
        Ok(dir)
    }

    pub(super) fn open_dir(dir: &DirCap, path: &RelPath) -> Result<DirCap, FsError> {
        let fd = rustix::fs::openat2(
            &dir.fd,
            path.to_slash_string(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            RESOLVE,
        )
        .map_err(map)?;
        Ok(DirCap { fd })
    }

    pub(super) fn open_file(
        dir: &DirCap,
        path: &RelPath,
        mode: OpenMode,
    ) -> Result<CapFile, FsError> {
        let base = OFlags::CLOEXEC | OFlags::NOFOLLOW;
        let flags = match mode {
            OpenMode::Read => base | OFlags::RDONLY,
            OpenMode::CreateExclusive => base | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            OpenMode::Append => base | OFlags::WRONLY | OFlags::APPEND,
        };
        // openat2 refuses a non-zero mode without O_CREAT (EINVAL).
        let create_mode = if mode == OpenMode::CreateExclusive {
            Mode::RUSR | Mode::WUSR
        } else {
            Mode::empty()
        };
        let fd = rustix::fs::openat2(&dir.fd, path.to_slash_string(), flags, create_mode, RESOLVE)
            .map_err(map)?;
        Ok(CapFile { fd })
    }

    pub(super) fn create_temp(dir: &DirCap) -> Result<(PathSeg, CapFile), FsError> {
        let mut bytes = [0u8; 16];
        rustix::rand::getrandom(&mut bytes, rustix::rand::GetRandomFlags::empty()).map_err(map)?;
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let name = PathSeg::parse(&format!("tmp-{hex}"))
            .map_err(|e| FsError::Os(std::io::Error::other(e)))?;
        let fd = rustix::fs::openat2(
            &dir.fd,
            name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
            RESOLVE,
        )
        .map_err(map)?;
        Ok((name, CapFile { fd }))
    }

    pub(super) fn remove_file(dir: &DirCap, path: &RelPath) -> Result<(), FsError> {
        let parent = path.parent().map(|p| open_dir(dir, &p)).transpose()?;
        let at = parent.as_ref().unwrap_or(dir);
        // unlinkat removes a final symbolic link itself and never follows it.
        rustix::fs::unlinkat(&at.fd, path.last().as_str(), AtFlags::empty()).map_err(map)
    }

    pub(super) fn read(file: &CapFile, buf: &mut [u8]) -> Result<usize, FsError> {
        rustix::io::read(&file.fd, buf).map_err(map)
    }

    pub(super) fn write(file: &CapFile, buf: &[u8]) -> Result<usize, FsError> {
        rustix::io::write(&file.fd, buf).map_err(map)
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::{CapFile, DirCap, FsError, OpenMode};
    use crate::path::{PathSeg, RelPath};

    pub(super) fn open_root(_path: &std::path::Path) -> Result<DirCap, FsError> {
        Err(FsError::Unsupported)
    }
    pub(super) fn open_dir(_dir: &DirCap, _path: &RelPath) -> Result<DirCap, FsError> {
        Err(FsError::Unsupported)
    }
    pub(super) fn open_file(
        _dir: &DirCap,
        _path: &RelPath,
        _mode: OpenMode,
    ) -> Result<CapFile, FsError> {
        Err(FsError::Unsupported)
    }
    pub(super) fn create_temp(_dir: &DirCap) -> Result<(PathSeg, CapFile), FsError> {
        Err(FsError::Unsupported)
    }
    pub(super) fn remove_file(_dir: &DirCap, _path: &RelPath) -> Result<(), FsError> {
        Err(FsError::Unsupported)
    }
    pub(super) fn read(_file: &CapFile, _buf: &mut [u8]) -> Result<usize, FsError> {
        Err(FsError::Unsupported)
    }
    pub(super) fn write(_file: &CapFile, _buf: &[u8]) -> Result<usize, FsError> {
        Err(FsError::Unsupported)
    }
}

impl DirCap {
    /// Opens the directory a manifest grants. Only the manifest loader
    /// calls this; there is no public string-path constructor.
    pub(crate) fn open_root(path: &std::path::Path) -> Result<Self, FsError> {
        imp::open_root(path)
    }

    /// A capability for the directory at `path` beneath this one.
    ///
    /// # Errors
    ///
    /// [`FsError::Os`] if it does not exist, is not a directory, or the path
    /// meets a symbolic link or mount point; [`FsError::Unsupported`] off
    /// Linux.
    pub fn open_dir(&self, path: &RelPath) -> Result<Self, FsError> {
        imp::open_dir(self, path)
    }

    /// Opens the file at `path` beneath this directory.
    ///
    /// # Errors
    ///
    /// [`FsError::Os`] if the open fails, including `ELOOP` for any symbolic
    /// link on the path and `EEXIST` for [`OpenMode::CreateExclusive`] on an
    /// existing name; [`FsError::Unsupported`] off Linux.
    pub fn open_file(&self, path: &RelPath, mode: OpenMode) -> Result<CapFile, FsError> {
        imp::open_file(self, path, mode)
    }

    /// Creates a new file with an unpredictable name, mode 0600, opened for
    /// reading and writing; a pre-planted file or link makes it fail.
    ///
    /// # Errors
    ///
    /// [`FsError::Os`] if creation fails; [`FsError::Unsupported`] off Linux.
    pub fn create_temp(&self) -> Result<(PathSeg, CapFile), FsError> {
        imp::create_temp(self)
    }

    /// Removes the file at `path`. A final symbolic link is removed, not
    /// followed.
    ///
    /// # Errors
    ///
    /// [`FsError::Os`] if removal fails; [`FsError::Unsupported`] off Linux.
    pub fn remove_file(&self, path: &RelPath) -> Result<(), FsError> {
        imp::remove_file(self, path)
    }
}

impl CapFile {
    /// Reads the whole file, failing rather than allocating past `limit`
    /// bytes (spec 4.12: budgets are mandatory parameters).
    ///
    /// # Errors
    ///
    /// [`FsError::BudgetExceeded`] if the file is longer than `limit`;
    /// [`FsError::Os`] on a read error.
    pub fn read_to_end(&self, limit: usize) -> Result<Vec<u8>, FsError> {
        let mut out = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = imp::read(self, &mut chunk)?;
            if n == 0 {
                return Ok(out);
            }
            let got = chunk.get(..n).unwrap_or(&[]);
            if out
                .len()
                .checked_add(got.len())
                .is_none_or(|total| total > limit)
            {
                return Err(FsError::BudgetExceeded { limit });
            }
            out.extend_from_slice(got);
        }
    }

    /// Writes all of `data`.
    ///
    /// # Errors
    ///
    /// [`FsError::Os`] on a write error.
    pub fn write_all(&self, mut data: &[u8]) -> Result<(), FsError> {
        while !data.is_empty() {
            let n = imp::write(self, data)?;
            if n == 0 {
                return Err(FsError::Os(io::Error::from(io::ErrorKind::WriteZero)));
            }
            data = data.get(n..).unwrap_or(&[]);
        }
        Ok(())
    }
}

/// Convenience: a one-segment path from text.
///
/// # Errors
///
/// Returns the grammar rule `text` breaks.
pub fn rel(text: &str) -> Result<RelPath, crate::path::PathSegError> {
    PathSeg::parse(text).map(RelPath::new)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("corten-std-{}-{name}", std::process::id()));
            if dir.exists() {
                std::fs::remove_dir_all(&dir).unwrap();
            }
            std::fs::create_dir_all(dir.join("jail")).unwrap();
            std::fs::write(dir.join("secret.txt"), b"outside").unwrap();
            Self(dir)
        }
        fn jail(&self) -> DirCap {
            DirCap::open_root(&self.0.join("jail")).unwrap()
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ignored = std::fs::remove_dir_all(&self.0);
        }
    }

    fn errno(r: Result<CapFile, FsError>) -> Option<i32> {
        match r {
            Err(FsError::Os(e)) => e.raw_os_error(),
            other => panic!("expected an OS error, got {other:?}"),
        }
    }

    #[test]
    fn reads_and_writes_inside() {
        let s = Scratch::new("rw");
        let jail = s.jail();
        let f = jail
            .open_file(&rel("a.txt").unwrap(), OpenMode::CreateExclusive)
            .unwrap();
        f.write_all(b"hello").unwrap();
        drop(f);
        let f = jail
            .open_file(&rel("a.txt").unwrap(), OpenMode::Read)
            .unwrap();
        assert_eq!(f.read_to_end(1024).unwrap(), b"hello");
        let f = jail
            .open_file(&rel("a.txt").unwrap(), OpenMode::Read)
            .unwrap();
        assert!(matches!(
            f.read_to_end(3),
            Err(FsError::BudgetExceeded { limit: 3 })
        ));
        let mode = std::fs::metadata(s.0.join("jail/a.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn symlink_out_of_the_jail_is_refused() {
        let s = Scratch::new("symlink");
        symlink(s.0.join("secret.txt"), s.0.join("jail/link")).unwrap();
        // Control: the link works for ordinary path resolution.
        assert_eq!(std::fs::read(s.0.join("jail/link")).unwrap(), b"outside");
        let r = s.jail().open_file(&rel("link").unwrap(), OpenMode::Read);
        assert_eq!(errno(r), Some(libc_eloop()));
    }

    #[test]
    fn symlink_to_a_directory_on_the_path_is_refused() {
        let s = Scratch::new("dirlink");
        symlink(&s.0, s.0.join("jail/up")).unwrap();
        assert!(
            std::fs::read(s.0.join("jail/up/secret.txt")).is_ok(),
            "control"
        );
        let path = rel("up")
            .unwrap()
            .join(PathSeg::parse("secret.txt").unwrap());
        let r = s.jail().open_file(&path, OpenMode::Read);
        assert_eq!(errno(r), Some(libc_eloop()));
    }

    #[test]
    fn exclusive_create_refuses_a_planted_name() {
        let s = Scratch::new("planted");
        std::fs::write(s.0.join("jail/report"), b"planted").unwrap();
        let r = s
            .jail()
            .open_file(&rel("report").unwrap(), OpenMode::CreateExclusive);
        assert_eq!(errno(r), Some(17)); // EEXIST
        symlink(s.0.join("secret.txt"), s.0.join("jail/report2")).unwrap();
        let r = s
            .jail()
            .open_file(&rel("report2").unwrap(), OpenMode::CreateExclusive);
        assert!(errno(r).is_some(), "a planted link must not be followed");
        assert_eq!(std::fs::read(s.0.join("secret.txt")).unwrap(), b"outside");
    }

    #[test]
    fn temp_files_are_unique_and_private() {
        let s = Scratch::new("temp");
        let jail = s.jail();
        let (a, fa) = jail.create_temp().unwrap();
        let (b, _fb) = jail.create_temp().unwrap();
        assert_ne!(a, b);
        assert!(a.as_str().starts_with("tmp-") && a.as_str().len() == 36);
        fa.write_all(b"x").unwrap();
        let mode = std::fs::metadata(s.0.join("jail").join(a.as_str()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn remove_does_not_follow_a_final_link() {
        let s = Scratch::new("remove");
        symlink(s.0.join("secret.txt"), s.0.join("jail/victim")).unwrap();
        s.jail().remove_file(&rel("victim").unwrap()).unwrap();
        assert!(s.0.join("secret.txt").exists());
        assert!(!s.0.join("jail/victim").exists());
    }

    #[test]
    fn subdirectories_are_capabilities_too() {
        let s = Scratch::new("subdir");
        std::fs::create_dir(s.0.join("jail/inner")).unwrap();
        let inner = s.jail().open_dir(&rel("inner").unwrap()).unwrap();
        inner
            .open_file(&rel("f").unwrap(), OpenMode::CreateExclusive)
            .unwrap();
        assert!(s.0.join("jail/inner/f").exists());
    }

    fn libc_eloop() -> i32 {
        40
    }
}
