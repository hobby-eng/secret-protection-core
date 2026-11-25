//! The Landlock layer: no file may be changed anywhere, and on newer kernels no TCP bind or connect,
//! no connection to UNIX sockets outside the layer and no signals to processes outside it. Reading
//! stays allowed. Rights the running kernel doesn't know are skipped.

use std::os::fd::BorrowedFd;

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, LandlockStatus, PathBeneath, RestrictSelfAttr,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetError, RulesetStatus, Scope,
};

/// The newest Landlock ABI whose rights the layer asks for: that of Linux 7.1.
const ASKED: ABI = ABI::V9;

/// What the layer allows beneath a granted folder: making files and folders, writing,
/// removing, and, from ABI 2 (Linux 5.19), links and renames between folders, which Landlock
/// lets through only when the file gains no right by them. ABI 1 refuses those moves.
fn folder_rights() -> BitFlags<AccessFs> {
    AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::WriteFile
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir
        | AccessFs::Refer
}

/// Whether the running kernel can put a layer on every thread at once (ABI 8, Linux 7.0).
pub(super) fn syncs() -> bool {
    // SAFETY: with a null attribute and the version flag the call only returns a number.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0_usize,
            1_u32,
        )
    };
    abi >= 8
}

/// The layer, with the rights of `folders` beneath each.
fn layer(folders: &[BorrowedFd<'_>]) -> Result<RulesetCreated, RulesetError> {
    let mut created = Ruleset::default()
        .handle_access(AccessFs::from_write(ASKED))
        .and_then(|ruleset| ruleset.handle_access(AccessNet::from_all(ASKED)))
        .and_then(|ruleset| ruleset.scope(Scope::AbstractUnixSocket | Scope::Signal))
        .and_then(Ruleset::create)?;
    for folder in folders {
        created = created.add_rule(PathBeneath::new(folder, folder_rights()))?;
    }
    Ok(created)
}

/// Applies the layer to the calling thread and the threads it starts afterwards. Returns
/// [`super::seccomp::LAYER`] when the kernel took it, with [`super::seccomp::SCOPE`] when it
/// has the signal scope (ABI 6, Linux 6.12) and [`super::seccomp::FOLDERS`] when it took the
/// folders' rules, and 0 when it refused or has no Landlock. A folder rule the kernel refuses
/// leaves the layer without any, closed everywhere.
/// With `sync`, on every thread at once (TSYNC, Linux 7.0), which the second value says.
/// TSYNC replaces a Landlock layer another thread had of its own, which can be wider for
/// that thread. A TSYNC the kernel refuses leaves a `first` layer to the calling thread, and
/// adds none to a thread that holds one, as the kernel takes at most 16.
pub(super) fn restrict_self(folders: &[BorrowedFd<'_>], sync: bool, first: bool) -> (u32, bool) {
    let (created, granted) = match layer(folders) {
        Err(_) if !folders.is_empty() => (layer(&[]), false),
        created => (created, !folders.is_empty()),
    };
    let taken = if granted { folders } else { &[] };
    let applied = created
        .and_then(|created| created.all_threads(sync))
        .and_then(RulesetCreated::restrict_self);
    let applied = match applied {
        Err(_) if sync && first => layer(taken).and_then(RulesetCreated::restrict_self),
        applied => applied,
    };
    match applied {
        Ok(status) if status.ruleset != RulesetStatus::NotEnforced => {
            let scoped = matches!(
                status.landlock,
                LandlockStatus::Available { effective_abi, .. } if effective_abi >= ABI::V6
            );
            let bits = super::seccomp::LAYER
                | (u32::from(scoped) * super::seccomp::SCOPE)
                | (u32::from(granted) * super::seccomp::FOLDERS);
            (bits, status.all_threads)
        }
        _ => (0, false),
    }
}
