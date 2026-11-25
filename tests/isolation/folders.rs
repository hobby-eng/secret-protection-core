//! Folders granted for writing, and the check of what else is open after isolation, each in a
//! role of its own: a granted folder takes the new files the program makes, nothing outside it
//! does, and shared memory made before isolation is named as a way out.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use secret_protection_core::{Isolation, Options, WritableFolder, open_channels};

use super::{ROLE, run, support};

/// The folder of the test a role works in, which the test removes after it.
const PLACE: &str = "SECRET_PROTECTION_CORE_TEST_PLACE";

pub(crate) fn checks() {
    run(
        "a granted folder takes new files and folders, and nothing outside it does",
        || role_ends_well("folders"),
    );
    run(
        "a folder that is no longer empty is not granted, and writes stay closed",
        || role_ends_well("stale-folder"),
    );
    run(
        "shared memory made before isolation is named until it is gone",
        || role_ends_well("shared-memory"),
    );
    #[cfg(target_os = "linux")]
    run(
        "folders granted with one thread stay open, and all_threads then reaches every thread",
        || role_ends_well("folders-then-threads"),
    );
}

/// Runs `role` in a child of its own, in a new folder of the test that is removed after it.
fn role_ends_well(role: &str) {
    let place = std::env::temp_dir().join(format!("spc-folders-{}-{role}", std::process::id()));
    fs::create_dir(&place).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .env(ROLE, role)
        .env(PLACE, &place)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    fs::remove_dir_all(&place).unwrap();
    support::role_ended(role, output.status, &output.stderr);
}

fn place() -> PathBuf {
    PathBuf::from(std::env::var_os(PLACE).unwrap())
}

/// A new file for writing only, mode 0600: the one form a granted folder takes.
fn new_file(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn refused<T: std::fmt::Debug>(result: io::Result<T>, what: &str) {
    assert!(result.is_err(), "{what} was not refused: {result:?}");
}

/// The `folders` role.
pub(crate) fn folders_role() {
    use std::io::Write;
    let place = place();
    let granted = WritableFolder::create(place.join("granted")).unwrap();
    assert!(granted.is_private());
    assert_eq!(
        WritableFolder::create(granted.path()).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    // Made before isolation, as a program makes all its folders: granted by a later call, none.
    let later = WritableFolder::create(place.join("later")).unwrap();
    let spare = WritableFolder::create(place.join("spare")).unwrap();
    let outside = place.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("before"), b"made before isolation").unwrap();
    let isolation = Isolation::enter_with_folders(Options::new(), &[&granted, &spare]);
    #[cfg(target_os = "linux")]
    if !landlock() {
        support::skip_role("the kernel has no Landlock");
    }
    assert!(
        isolation.folder_writes && isolation.no_file_changes,
        "{isolation:?}"
    );
    let again = Isolation::enter_with_folders(Options::new(), &[&later]);
    assert!(!again.folder_writes, "a later call's folder: {again:?}");
    refused(
        new_file(&later.path().join("new")),
        "a new file in a later folder",
    );
    let inside = granted.path();
    new_file(&inside.join("file"))
        .and_then(|mut file| file.write_all(b"written inside"))
        .unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(inside.join("sub"))
        .unwrap();
    new_file(&inside.join("sub/nested")).unwrap();
    fs::rename(inside.join("sub/nested"), inside.join("sub/renamed")).unwrap();
    fs::remove_file(inside.join("sub/renamed")).unwrap();
    fs::remove_dir_all(inside.join("sub")).unwrap();
    refused(new_file(&outside.join("new")), "a new file outside");
    refused(new_file(&inside.join("../escaped")), "a new file by ..");
    refused(
        fs::DirBuilder::new()
            .mode(0o700)
            .create(outside.join("dir")),
        "a folder outside",
    );
    refused(fs::remove_file(outside.join("before")), "a removal outside");
    refused(
        fs::rename(inside.join("file"), outside.join("taken-out")),
        "a move out of the folder",
    );
    refused(
        fs::rename(outside.join("before"), inside.join("taken-in")),
        "a move into the folder",
    );
    // The empty one, so that only the rule can refuse it, not a folder that holds files.
    let removed = fs::remove_dir(spare.path()).unwrap_err();
    assert!(
        matches!(removed.raw_os_error(), Some(libc::EACCES | libc::EPERM)),
        "the removal of a granted folder itself: {removed}"
    );
    refused(
        fs::rename(inside, place.join("renamed-folder")),
        "a rename of the folder itself",
    );
    refused(
        std::os::unix::fs::symlink("/etc", inside.join("symlink")),
        "a symbolic link",
    );
    refused(
        fs::hard_link(outside.join("before"), inside.join("pulled-in")),
        "a link to a file outside",
    );
    #[cfg(target_os = "linux")]
    linux_forms(inside);
}

/// Whether the kernel has Landlock.
#[cfg(target_os = "linux")]
fn landlock() -> bool {
    // SAFETY: with a null attribute and the version flag the call only returns a number.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0_usize,
            1_u32,
        )
    };
    abi >= 1
}

/// Asserts that the call that returned `answer` was refused by the filter (EACCES).
#[cfg(target_os = "linux")]
fn filtered(answer: libc::c_long, what: &str) {
    let error = io::Error::last_os_error();
    assert_eq!(
        (answer, error.raw_os_error()),
        (-1, Some(libc::EACCES)),
        "{what}: {error}"
    );
}

/// What the filter lets through on Linux beyond the place: only the granted forms.
#[cfg(target_os = "linux")]
fn linux_forms(inside: &Path) {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let name = |path: &Path| CString::new(path.as_os_str().as_bytes()).unwrap();
    let file = inside.join("file");
    fs::hard_link(&file, inside.join("link")).unwrap();
    fs::rename(inside.join("link"), inside.join("moved")).unwrap();
    refused(
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(inside.join("wide")),
        "a file others can read",
    );
    refused(
        fs::OpenOptions::new().write(true).open(&file),
        "an existing file opened for writing",
    );
    refused(
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .mode(0o600)
            .open(inside.join("truncated")),
        "a truncating open",
    );
    refused(
        fs::DirBuilder::new()
            .mode(0o755)
            .create(inside.join("wide-dir")),
        "a folder others can read",
    );
    refused(
        fs::create_dir(inside.join("default-dir")),
        "a folder of mode 0777",
    );
    let (moved, file_name, folder) = (name(&inside.join("moved")), name(&file), name(inside));
    let linked = name(&inside.join("by-descriptor"));
    // SAFETY: each call reads NUL-terminated paths and integers that live for it.
    unsafe {
        let call = |flags: libc::c_uint| {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                moved.as_ptr(),
                libc::AT_FDCWD,
                file_name.as_ptr(),
                flags,
            )
        };
        filtered(call(libc::RENAME_EXCHANGE), "an exchange of names");
        filtered(call(libc::RENAME_WHITEOUT), "a whiteout");
        let follow = libc::linkat(
            libc::AT_FDCWD,
            moved.as_ptr(),
            libc::AT_FDCWD,
            linked.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        );
        filtered(follow.into(), "a link that follows symbolic links");
        let temporary = libc::open(folder.as_ptr(), libc::O_TMPFILE | libc::O_WRONLY, 0o600);
        filtered(temporary.into(), "an unnamed temporary file");
    }
    let reading = fs::File::open(&file).unwrap();
    // SAFETY: an open descriptor, an empty name and a NUL-terminated path that live for the call.
    let by_descriptor = unsafe {
        libc::linkat(
            reading.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            linked.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    filtered(by_descriptor.into(), "a link by descriptor");
    // A descriptor opened for reading cannot be opened again for writing through /proc.
    refused(
        new_file(Path::new(&format!("/proc/self/fd/{}", reading.as_raw_fd()))),
        "a reopening through /proc",
    );
}

/// The `stale-folder` role: a file put into the folder before isolation keeps it from being
/// granted, and the filter then stays closed for it as everywhere.
pub(crate) fn stale_folder_role() {
    let granted = WritableFolder::create(place().join("granted")).unwrap();
    fs::write(granted.path().join("put-in"), b"before").unwrap();
    let isolation = Isolation::enter_with_folders(Options::new(), &[&granted]);
    assert!(!isolation.folder_writes, "{isolation:?}");
    refused(
        new_file(&granted.path().join("new")),
        "a new file in a stale folder",
    );
}

/// The `shared-memory` role: a shared mapping made before isolation is named by the check, this
/// crate's own secret memory is not, and once the mapping is gone the check passes.
pub(crate) fn shared_memory_role() {
    let length = 4096;
    // SAFETY: a new anonymous shared mapping, which this role alone uses and unmaps below.
    let shared = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANON,
            -1,
            0,
        )
    };
    assert_ne!(shared, libc::MAP_FAILED);
    // A file mapped shared but opened for reading can never be written through: no way out.
    let path = place().join("read-only");
    fs::write(&path, [0_u8; 4096]).unwrap();
    let reading = fs::File::open(&path).unwrap();
    // SAFETY: a new read-only shared mapping of a file opened for reading, kept to the end.
    let read_only = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ,
            libc::MAP_SHARED,
            std::os::fd::AsRawFd::as_raw_fd(&reading),
            0,
        )
    };
    assert_ne!(read_only, libc::MAP_FAILED);
    drop(reading);
    // A file mapped shared for writing keeps reaching the file once its descriptor is closed.
    let written = place().join("written");
    fs::write(&written, [0_u8; 4096]).unwrap();
    let writing = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&written)
        .unwrap();
    // SAFETY: a new shared mapping of a file opened for reading and writing, kept to the end.
    let file_mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            std::os::fd::AsRawFd::as_raw_fd(&writing),
            0,
        )
    };
    assert_ne!(file_mapping, libc::MAP_FAILED);
    drop(writing);
    let _isolation = Isolation::enter();
    let secret = secret_protection_core::Secret::with_capacity(32);
    let streams = [0, 1, 2];
    let found = open_channels().unwrap().only(&streams).unwrap_err();
    assert!(found.complete, "{found:?}");
    assert!(found.channels.is_empty(), "{found:?}");
    let mut starts: Vec<usize> = (found.shared_mappings.iter())
        .map(|mapping| mapping.start)
        .collect();
    starts.sort_unstable();
    let mut expected = [shared as usize, file_mapping as usize];
    expected.sort_unstable();
    assert_eq!(starts, expected, "{found:?}");
    // SAFETY: the mappings made above, which nothing refers to any more.
    assert_eq!(unsafe { libc::munmap(shared, length) }, 0);
    // SAFETY: as above.
    assert_eq!(unsafe { libc::munmap(file_mapping, length) }, 0);
    let after = open_channels().unwrap();
    assert_eq!(after.only(&streams), Ok(()), "{after:?}");
    drop(secret);
}

/// The `folders-then-threads` role: folders granted while the process had one thread, then a
/// call with `all_threads` once another thread runs. The layer and the filter reached every
/// thread already, so nothing goes in again, the whole process holds and the folder stays open.
#[cfg(target_os = "linux")]
pub(crate) fn folders_then_threads_role() {
    use secret_protection_core::{Protection, Reach};
    let granted = WritableFolder::create(place().join("granted")).unwrap();
    let first = Isolation::enter_with_folders(Options::new(), &[&granted]);
    if !landlock() {
        support::skip_role("the kernel has no Landlock");
    }
    assert!(first.folder_writes && first.whole_process, "{first:?}");
    let (park, parked) = std::sync::mpsc::channel::<()>();
    let sibling = std::thread::spawn(move || {
        let _ = parked.recv();
    });
    let later = Isolation::enter_with(Options::new().all_threads());
    let reach = (later.measures().into_iter())
        .find(|measure| measure.protection == Protection::NoFileChanges)
        .map(|measure| measure.reach);
    assert_eq!(reach, Some(Reach::Process), "{later:?}");
    assert!(later.whole_process, "{later:?}");
    new_file(&granted.path().join("still-open")).unwrap();
    drop(park);
    sibling.join().unwrap();
}
