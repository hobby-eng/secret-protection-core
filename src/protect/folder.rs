//! [`WritableFolder`]: a folder made new before isolation, the one place where
//! [`super::Isolation::enter_with_folders`] lets a program write.
#![allow(
    unsafe_code,
    reason = "mkdirat, fchmod, openat, unlinkat, fstat and the directory listing are foreign \
              functions"
)]
#![cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_os = "macos")),
    allow(
        dead_code,
        reason = "only systems that grant folders check one before they grant it"
    )
)]

use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// How a folder is held: on Linux a handle that reads nothing, which Landlock takes.
#[cfg(any(target_os = "linux", target_os = "android"))]
const HOLD: libc::c_int = libc::O_PATH;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const HOLD: libc::c_int = libc::O_RDONLY;

/// A folder that [`WritableFolder::create`] made new, this user's, and held open, so that
/// isolation can let the program write beneath it and nowhere else. Isolation grants it only
/// while its path still leads to it and it is empty.
pub struct WritableFolder {
    descriptor: OwnedFd,
    path: PathBuf,
    /// Device and inode, as made.
    identity: (u64, u64),
    private: bool,
}

impl WritableFolder {
    /// Makes the folder at `path` with mode 0700, inside its parent as opened once; it must not
    /// exist yet. Refused, and the folder removed again, when the folder made is not this
    /// user's. A file system that keeps no Unix modes (FAT, exFAT, NTFS, many network mounts)
    /// gives it the mount's: [`WritableFolder::is_private`] says which. Isolation checks the path
    /// as given, so a relative one stops leading to it after a change of directory.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "the path names no folder")
        })?;
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let parent = open_at(libc::AT_FDCWD, parent.as_os_str().as_bytes(), HOLD)?;
        let name = CString::new(name.as_bytes())?;
        // SAFETY: a NUL-terminated name, relative to the parent held. mkdirat refuses a name
        // that exists and follows no symbolic link at it.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // The folder made, as the parent lists it now: the one `hold` must open, and the only
        // one a failure removes again.
        let made = identity(&entry(&parent, &name)?);
        let held = Self::hold(&parent, &name, path, made);
        // SAFETY: geteuid takes nothing and only answers.
        let user = unsafe { libc::geteuid() };
        if held.is_err()
            && entry(&parent, &name).is_ok_and(|now| identity(&now) == made && now.st_uid == user)
        {
            // SAFETY: as above; removes the folder this call made, which is still empty.
            unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
        }
        held
    }

    /// Holds the folder `name` that `create` made in `parent` as `made`, after setting its mode
    /// to 0700 against a umask that took the owner's write or search bit, through the folder
    /// itself, never a link or another folder put in its place; a file system without modes
    /// ignores it. A umask that took the owner's read bit makes it fail, and `create` removes
    /// the folder again.
    fn hold(parent: &OwnedFd, name: &CStr, path: &Path, made: (u64, u64)) -> io::Result<Self> {
        let opened = open_at(
            parent.as_raw_fd(),
            name.to_bytes(),
            libc::O_RDONLY | libc::O_NOFOLLOW,
        )?;
        let found = status(opened.as_raw_fd())?;
        // SAFETY: geteuid takes nothing and only answers.
        if identity(&found) != made || found.st_uid != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the folder made was replaced, or is not this user's",
            ));
        }
        // SAFETY: fchmod takes a descriptor this function owns and a mode.
        unsafe { libc::fchmod(opened.as_raw_fd(), 0o700) };
        let descriptor = open_at(opened.as_raw_fd(), b".", HOLD)?;
        let status = status(descriptor.as_raw_fd())?;
        let private = status.st_mode & 0o777 == 0o700
            && !past_the_mode(opened.as_raw_fd())
            && settled_above(descriptor.as_raw_fd());
        Ok(Self {
            descriptor,
            path: path.to_owned(),
            identity: made,
            private,
        })
    }

    /// The path it was made at.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether only this user can reach it, as made: false where the file system keeps no Unix
    /// modes. On macOS also false where an access list on it or above it allows anything to
    /// anyone, or where someone else could move it or a folder above it (docs/API.md).
    pub fn is_private(&self) -> bool {
        self.private
    }

    /// Whether its path still leads to the folder held, and it is empty: what isolation checks
    /// before it grants it, as the program writes by the path and the grant follows the folder.
    pub(crate) fn still_new(&self) -> bool {
        std::fs::symlink_metadata(&self.path)
            .is_ok_and(|now| (now.dev(), now.ino()) == self.identity)
            && empty(self.descriptor.as_raw_fd()).unwrap_or(false)
    }
}

impl AsFd for WritableFolder {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

impl AsRawFd for WritableFolder {
    fn as_raw_fd(&self) -> RawFd {
        self.descriptor.as_raw_fd()
    }
}

impl fmt::Debug for WritableFolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WritableFolder")
            .field("path", &self.path)
            .field("private", &self.private)
            .finish_non_exhaustive()
    }
}

/// Opens `name`, relative to `directory`, as a directory: an owned descriptor.
fn open_at(directory: RawFd, name: &[u8], flags: libc::c_int) -> io::Result<OwnedFd> {
    let name = CString::new(name)?;
    // SAFETY: a NUL-terminated name, read for the call.
    let opened = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            flags | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if opened < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor, owned once here.
    Ok(unsafe { OwnedFd::from_raw_fd(opened) })
}

/// The entry `name` in `parent`, not followed if it is a link.
fn entry(parent: &OwnedFd, name: &CStr) -> io::Result<libc::stat> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: a NUL-terminated name; fstatat fills the stat when it succeeds.
    let read = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if read != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: filled by the call that just succeeded.
    Ok(unsafe { status.assume_init() })
}

/// Whether no one but this user and root can move the folder held by `descriptor`: each folder
/// above it, up to the root, belongs to one of them, and its group and others may write in it
/// only with the sticky bit, which keeps them from moving what is not theirs; no access list
/// there allows anything to anyone. Only macOS, whose sandbox grants a folder by its path; a
/// Landlock rule holds the folder itself, wherever it is moved.
fn settled_above(descriptor: RawFd) -> bool {
    if !cfg!(target_os = "macos") {
        return true;
    }
    // SAFETY: geteuid takes nothing and only answers.
    let user = unsafe { libc::geteuid() };
    let settled = |status: &libc::stat| {
        let writable_by_others = status.st_mode & 0o022 != 0;
        let sticky = status.st_mode & libc::S_ISVTX != 0;
        (status.st_uid == user || status.st_uid == 0) && (!writable_by_others || sticky)
    };
    let Ok(mut current) = open_at(descriptor, b"..", HOLD) else {
        return false;
    };
    // Deeper than any path can be, so that a loop the system should never show ends.
    for _ in 0..libc::PATH_MAX {
        let (Ok(here), Ok(above)) = (
            status(current.as_raw_fd()),
            open_at(current.as_raw_fd(), b"..", HOLD),
        ) else {
            return false;
        };
        if !settled(&here) || past_the_mode(current.as_raw_fd()) {
            return false;
        }
        // The root is its own parent.
        match status(above.as_raw_fd()) {
            Ok(top) if identity(&top) == identity(&here) => return true,
            Ok(_) => current = above,
            Err(_) => return false,
        }
    }
    false
}

/// Whether others may reach the folder held by `descriptor` past its mode, or it cannot be
/// told: on macOS an access list that allows anything to anyone, or a volume mounted to ignore
/// owners and modes. Elsewhere the mode holds what a list may grant, and iOS gives each app its
/// own user.
#[cfg(target_os = "macos")]
fn past_the_mode(descriptor: RawFd) -> bool {
    crate::os::listed_access(descriptor) || crate::os::owners_ignored(descriptor)
}

#[cfg(not(target_os = "macos"))]
fn past_the_mode(_descriptor: RawFd) -> bool {
    false
}

fn status(descriptor: RawFd) -> io::Result<libc::stat> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat fills the stat when it succeeds.
    if unsafe { libc::fstat(descriptor, status.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: filled by the call that just succeeded.
    Ok(unsafe { status.assume_init() })
}

/// Device and inode as `MetadataExt` gives them, which `still_new` compares against.
#[allow(
    clippy::useless_conversion,
    clippy::cast_sign_loss,
    clippy::unnecessary_cast,
    reason = "the types of st_dev and st_ino differ between systems; MetadataExt casts the same way"
)]
fn identity(status: &libc::stat) -> (u64, u64) {
    (status.st_dev as u64, u64::from(status.st_ino))
}

/// Clears errno, which readdir sets only on an error and leaves as it is at the end.
fn clear_errno() {
    // SAFETY: the calling thread's errno, which this thread alone writes.
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location() = 0;
    };
    // SAFETY: as above.
    #[cfg(target_os = "android")]
    unsafe {
        *libc::__errno() = 0;
    };
    // SAFETY: as above.
    #[cfg(target_vendor = "apple")]
    unsafe {
        *libc::__error() = 0;
    };
}

/// Whether the folder held by `descriptor` lists nothing but `.` and `..`.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn empty(descriptor: RawFd) -> io::Result<bool> {
    let listed = open_at(descriptor, b".", libc::O_RDONLY)?;
    // SAFETY: fdopendir takes over the descriptor, which closedir closes with the listing.
    let directory = unsafe { libc::fdopendir(listed.as_raw_fd()) };
    if directory.is_null() {
        return Err(io::Error::last_os_error());
    }
    std::mem::forget(listed);
    let read = loop {
        clear_errno();
        // SAFETY: readdir reads the listing opened above and returns an entry it owns, or null.
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            break if error.raw_os_error() == Some(0) {
                Ok(true)
            } else {
                Err(error)
            };
        }
        // SAFETY: an entry holds a NUL-terminated name, valid until the next readdir.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name != c"." && name != c".." {
            break Ok(false);
        }
    };
    // SAFETY: closes the listing opened above, and its descriptor.
    unsafe { libc::closedir(directory) };
    read
}

/// Other systems grant no folder, so none is checked.
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn empty(_descriptor: RawFd) -> io::Result<bool> {
    Err(io::ErrorKind::Unsupported.into())
}
