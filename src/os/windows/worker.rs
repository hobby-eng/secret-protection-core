//! The worker process on Windows: started in an AppContainer without capabilities, and without
//! one handle of its parent's. The two talk through a named pipe that the worker opens by name.

use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::PSID;
use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_WRITE_DATA};

/// What a worker may do with its pipe: read it and write to it, and no more, such as making a
/// further instance of it.
const CLIENT_ACCESS: u32 = FILE_GENERIC_READ | FILE_WRITE_DATA;
/// The name of every worker's pipe, before its 32 random hexadecimal digits.
use super::Descriptor;
use crate::worker::PIPE_PREFIX;
/// The pipe's buffers, each way.
const PIPE_BUFFER: u32 = 64 << 10;
/// How long a worker keeps trying its pipe while another process holds it.
const PATIENCE: Duration = Duration::from_secs(1);
/// The variables of this process that a worker gets beside its own: without them Windows starts
/// no process in an AppContainer, whose own folder it then puts in the place of the last three.
const SYSTEM_VARIABLES: [&str; 4] = ["SystemRoot", "LOCALAPPDATA", "TEMP", "TMP"];

/// The parent's end of a worker: its pipe, as one handle to write to and one to read from, and
/// the process.
pub(crate) struct WorkerProcess {
    pub(crate) to: Option<File>,
    pub(crate) from: Option<File>,
    process: OwnedHandle,
    id: u32,
    launch_nonce: u128,
}

impl WorkerProcess {
    /// Starts this program again in its own AppContainer: no capabilities, no console, no handle
    /// inherited, and an environment containing [`SYSTEM_VARIABLES`] and the worker variable with
    /// its options, pipe name and launch nonce. The program file must be readable by less
    /// privileged app containers (Program Files is), or Windows refuses to start it. No worker on
    /// the terminal here.
    pub(crate) fn start(
        setting: &str,
        terminal: bool,
        deadline: Option<std::time::Instant>,
    ) -> io::Result<Self> {
        use std::os::windows::ffi::OsStrExt;
        if terminal {
            return Err(io::ErrorKind::Unsupported.into());
        }
        // The profile, the pipe and CreateProcessW are calls that cannot be cut short: the deadline
        // is read before them and, in `accept`, right after.
        if passed(deadline) {
            return Err(late());
        }
        let program = std::env::current_exe()?;
        let path: Vec<u16> = program.as_os_str().encode_wide().chain([0]).collect();
        let container = Container::of(&path)?;
        let (pipe, name) = listen(&container)?;
        let launch_nonce = random_u128()?;
        let (process, id) =
            container.start(&path, &format!("{setting},{name},{launch_nonce:032x}"))?;
        let mut worker = Self {
            to: None,
            from: None,
            process,
            id,
            launch_nonce,
        };
        let process: HANDLE = worker.process.as_raw_handle().cast();
        let accepted = accept(&pipe, process, id, deadline).and_then(|()| {
            if passed(deadline) {
                Err(late())
            } else {
                Ok(())
            }
        });
        match accepted.and_then(|()| pipe.try_clone()) {
            Ok(second) => {
                worker.to = Some(File::from(pipe));
                worker.from = Some(File::from(second));
                Ok(worker)
            }
            Err(error) => {
                drop(pipe);
                worker.finish();
                Err(error)
            }
        }
    }

    /// Runs `work` under one watchdog for the whole `deadline`, so that its reads and writes wait
    /// without one each.
    pub(crate) fn exchanging<T>(
        &mut self,
        deadline: Option<std::time::Instant>,
        work: impl FnOnce(&mut Self, Option<std::time::Instant>) -> io::Result<T>,
    ) -> io::Result<T> {
        if deadline.is_none() {
            return work(self, None);
        }
        let watched = self.process.try_clone()?;
        within(&watched, deadline, || work(self, None))
    }

    /// Reads all of `buffer` from the worker; with a `deadline`, ends the worker when it passes
    /// and fails with `TimedOut`.
    pub(crate) fn read_exact_until(
        &mut self,
        buffer: &mut [u8],
        deadline: Option<std::time::Instant>,
    ) -> io::Result<()> {
        let from = self.from.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        within(&self.process, deadline, || from.read_exact(buffer))
    }

    /// Writes all of `data` to the worker; with a `deadline`, as [`Self::read_exact_until`].
    pub(crate) fn write_all_until(
        &mut self,
        data: &[u8],
        deadline: Option<std::time::Instant>,
    ) -> io::Result<()> {
        let to = self.to.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        within(&self.process, deadline, || {
            to.write_all(data)?;
            to.flush()
        })
    }

    /// [`Self::observe_threads_now`] within `deadline`.
    pub(crate) fn observe_threads(
        &mut self,
        deadline: Option<std::time::Instant>,
    ) -> io::Result<()> {
        let watched = self.process.try_clone()?;
        within(&watched, deadline, || self.observe_threads_now())
    }

    /// The pipe client has already been matched to this worker's PID. Keep its exact
    /// process object live throughout each kernel inventory before sending the roster.
    fn observe_threads_now(&mut self) -> io::Result<()> {
        use super::threads::{Phase, inventory};
        use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        let process = self.process.as_raw_handle().cast();
        let running = || {
            // SAFETY: the parent owns this process handle with synchronization rights.
            if unsafe { WaitForSingleObject(process, 0) } == WAIT_TIMEOUT {
                Ok(())
            } else {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
        };
        let from = self.from.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        let to = self.to.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        running()?;
        to.write_all(&self.launch_nonce.to_le_bytes())?;
        for phase in [Phase::Access, Phase::Integrity] {
            let mut request = [0; 4];
            from.read_exact(&mut request)?;
            if request != phase.tag() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            running()?;
            let ids = inventory(self.id, None).unwrap_or_default();
            running()?;
            let mut reply = Vec::with_capacity(4 + 4 * ids.len());
            reply.extend_from_slice(&(ids.len() as u32).to_le_bytes());
            for id in ids {
                reply.extend_from_slice(&id.to_le_bytes());
            }
            to.write_all(&reply)?;
        }
        Ok(())
    }

    /// Closes both pipes: a worker that waits to read ends, and so does one that waits to write.
    pub(crate) fn close(&mut self) {
        self.to = None;
        self.from = None;
    }

    /// Closes both pipes and waits for the worker; one still running after the grace time is
    /// ended and given as long again, so that this never waits for ever. Returns whether the
    /// worker ended.
    pub(crate) fn finish(&mut self) -> bool {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
        self.close();
        let process = self.process.as_raw_handle().cast();
        let grace = u32::try_from(crate::os::GRACE.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: waits on, and if need be ends, the process whose handle this value owns. A
        // worker that ended between the wait and the termination refuses it: the second wait
        // decides.
        unsafe {
            WaitForSingleObject(process, grace) == WAIT_OBJECT_0 || {
                TerminateProcess(process, 1);
                WaitForSingleObject(process, grace) == WAIT_OBJECT_0
            }
        }
    }
}

/// Runs `work`; with a `deadline`, a watchdog ends the worker if `work` has not returned by then, so
/// that a pipe call waiting on it fails, and the result is `TimedOut`. One state decides which came
/// first: the work marks it done, or the watchdog marks it fired before it ends the worker, so a
/// worker whose work ended in time is never ended for being late.
fn within<T>(
    process: &OwnedHandle,
    deadline: Option<std::time::Instant>,
    work: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::mpsc::channel;
    use windows_sys::Win32::System::Threading::TerminateProcess;
    const RUNNING: u8 = 0;
    const DONE: u8 = 1;
    const FIRED: u8 = 2;
    let Some(deadline) = deadline else {
        return work();
    };
    let end = || {
        // SAFETY: ends the worker through a handle the caller owns, with that right.
        unsafe { TerminateProcess(process.as_raw_handle().cast(), 1) };
    };
    if passed(Some(deadline)) {
        end();
        return Err(late());
    }
    let state = Arc::new(AtomicU8::new(RUNNING));
    let watched = process.try_clone()?;
    let (done, waiting) = channel::<()>();
    let watchdog = {
        let state = Arc::clone(&state);
        std::thread::Builder::new()
            .name("worker-deadline".into())
            .spawn(move || {
                // Woken when the work ends, or at the deadline.
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                let _ = waiting.recv_timeout(left);
                let fired = state
                    .compare_exchange(RUNNING, FIRED, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok();
                if fired {
                    // SAFETY: ends the worker through a handle this thread owns, with that right.
                    unsafe { TerminateProcess(watched.as_raw_handle().cast(), 1) };
                }
            })?
    };
    let result = work();
    let in_time = state
        .compare_exchange(RUNNING, DONE, Ordering::AcqRel, Ordering::Acquire)
        .is_ok();
    let finished = std::time::Instant::now();
    drop(done);
    let _ = watchdog.join();
    // The clock decides as well: work that ended past the deadline failed, even before the
    // watchdog ran.
    if !in_time || finished > deadline {
        end();
        return Err(late());
    }
    result
}

/// Whether `deadline` has passed.
fn passed(deadline: Option<std::time::Instant>) -> bool {
    deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline)
}

/// The error of a deadline that passed.
fn late() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "the worker did not answer in time")
}

/// Generate independent values for the public pipe name and the private startup handshake.
fn random_u128() -> io::Result<u128> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let mut random = [0_u8; 16];
    // SAFETY: the call fills the sixteen bytes it is given.
    let filled = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            random.as_mut_ptr(),
            random.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } == 0;
    if !filled {
        return Err(io::Error::other(
            "Windows could not generate worker startup randomness",
        ));
    }
    Ok(u128::from_le_bytes(random))
}

/// Makes the pipe of one worker and returns it with its name. Its access list takes this user,
/// in `container` or in none: Windows gives an app container what the user's entry and the
/// container's both give. It has one instance, so one process holds it at a time, and none
/// inherits it.
fn listen(container: &Container) -> io::Result<(OwnedHandle, String)> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE,
    };
    let name = format!("{PIPE_PREFIX}{:032x}", random_u128()?);
    // The user and the container may read and write; the owner's own rights end at reading
    // this list; the low label lets a process of low integrity write.
    let access = format!(
        "D:P(A;;{CLIENT_ACCESS:#x};;;{})(A;;{CLIENT_ACCESS:#x};;;{})(A;;RC;;;OW)S:(ML;;NW;;;LW)",
        user()?,
        sid_text(container.0)?
    );
    let access: Vec<u16> = access.encode_utf16().chain([0]).collect();
    let descriptor = Descriptor::of(access.as_ptr())?;
    let attributes = descriptor.attributes();
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    // SAFETY: the name is NUL-terminated and the attributes live for the call, which returns a
    // new handle or INVALID_HANDLE_VALUE. A name that is taken is refused: one instance only.
    let pipe = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            PIPE_BUFFER,
            PIPE_BUFFER,
            0,
            &attributes,
        )
    };
    let error = io::Error::last_os_error();
    drop(descriptor);
    if pipe == INVALID_HANDLE_VALUE {
        return Err(error);
    }
    // SAFETY: the handle was just made and nothing else owns it.
    Ok((unsafe { OwnedHandle::from_raw_handle(pipe.cast()) }, name))
}

/// Waits for the worker to open `pipe` and takes no one else: the process at the other end must
/// be number `id`. Another process that opens it first is put off, and the pipe listens again.
/// An error when the worker ends first or `deadline` passes. From then on the pipe waits for
/// reads and writes.
fn accept(
    pipe: &OwnedHandle,
    process: HANDLE,
    id: u32,
    deadline: Option<std::time::Instant>,
) -> io::Result<()> {
    use windows_sys::Win32::Foundation::{
        ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, GetLastError, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, DisconnectNamedPipe, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
        PIPE_WAIT, SetNamedPipeHandleState,
    };
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    let pipe: HANDLE = pipe.as_raw_handle().cast();
    loop {
        // Checked on every turn, also after another process was put off: one that keeps taking
        // the pipe holds the start no longer than the deadline or the worker's life.
        // SAFETY: asks, without waiting, whether the worker has ended.
        if unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0 {
            return Err(io::Error::other("the worker did not open its pipe"));
        }
        if passed(deadline) {
            return Err(late());
        }
        // SAFETY: the pipe does not wait, so the call returns at once; the error is its own.
        // Such a pipe answers yes only to say that it listens again after a client was put off.
        let (listens, error) =
            unsafe { (ConnectNamedPipe(pipe, ptr::null_mut()) != 0, GetLastError()) };
        if !listens && (error == ERROR_PIPE_CONNECTED || error == ERROR_NO_DATA) {
            let mut client = 0;
            // SAFETY: the call writes the number of the process at the other end.
            let known = unsafe { GetNamedPipeClientProcessId(pipe, &mut client) } != 0;
            if known && client == id {
                break;
            }
            // Another process took the pipe, or took it and left: it is put off, and the pipe
            // listens for the worker again. Nothing was written to it.
            // SAFETY: ends the connection of this instance, which this process owns.
            if unsafe { DisconnectNamedPipe(pipe) } == 0 {
                return Err(io::Error::last_os_error());
            }
            continue;
        }
        if !(listens || error == ERROR_PIPE_LISTENING) {
            return Err(io::Error::other("the worker did not open its pipe"));
        }
        std::thread::sleep(crate::os::STEP);
    }
    let waits = PIPE_READMODE_BYTE | PIPE_WAIT;
    // SAFETY: the call reads one mode word, which lives for the call.
    if unsafe { SetNamedPipeHandleState(pipe, &waits, ptr::null(), ptr::null()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The SID of the user this process runs as, as text.
fn user() -> io::Result<String> {
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token = ptr::null_mut();
    // SAFETY: opens the token of this process for reading; closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // TOKEN_USER and the SID it points to: well within 128 bytes, in words aligned for the
    // pointer.
    let mut buffer = [0_u64; 16];
    let mut length = 0;
    // SAFETY: the call writes at most the buffer's length into it, and the length it needed.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size_of::<[u64; 16]>() as u32,
            &mut length,
        )
    } != 0;
    let error = io::Error::last_os_error();
    // SAFETY: closes the token opened above, once.
    unsafe { CloseHandle(token) };
    if !read {
        return Err(error);
    }
    // SAFETY: the call filled the buffer with a TOKEN_USER whose SID lies inside it.
    sid_text(unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid })
}

/// A SID as the text an access list names it by.
pub(super) fn sid_text(sid: PSID) -> io::Result<String> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: the SID is valid; the call allocates a NUL-terminated string, freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the string ends with a NUL and lives until it is freed, once, after its last use.
    unsafe {
        let length = (0..).take_while(|&at| *text.add(at) != 0).count();
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, length));
        LocalFree(text.cast());
        Ok(sid)
    }
}

/// The SID of the program's AppContainer, freed when dropped.
struct Container(PSID);

impl Container {
    /// The AppContainer of the program at `path` (NUL-terminated UTF-16), made at its first start:
    /// one per program, named after the FNV-1a digest of its path.
    fn of(path: &[u16]) -> io::Result<Self> {
        use windows_sys::Win32::Security::Isolation::{
            CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
        };
        let digest = path.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, &unit| {
            (hash ^ u64::from(unit)).wrapping_mul(0x0100_0000_01b3)
        });
        let name: Vec<u16> = format!("secret-protection-core.{digest:016x}")
            .encode_utf16()
            .chain([0])
            .collect();
        let mut sid = ptr::null_mut();
        // SAFETY: the names are NUL-terminated; the call writes the container's SID into `sid`,
        // which `Container` frees. A profile made by an earlier start answers ERROR_ALREADY_EXISTS.
        let made = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                name.as_ptr(),
                name.as_ptr(),
                ptr::null(),
                0,
                &mut sid,
            )
        } >= 0;
        let mut derived = || {
            // SAFETY: as above, for a profile that exists.
            unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) >= 0 }
        };
        if made || derived() {
            Ok(Self(sid))
        } else {
            Err(io::Error::other(
                "Windows made no AppContainer for the worker",
            ))
        }
    }

    /// Starts the program at `path` in this AppContainer, without capabilities, without one
    /// handle of this process's and without standard streams, with the worker's variable and
    /// [`SYSTEM_VARIABLES`] as its environment. Returns the process and its number. It starts
    /// suspended and runs only once its token's default list is the start-up list: a thread that
    /// Windows starts in it before its census, such as the loader's, is as closed as the first.
    fn start(&self, path: &[u16], setting: &str) -> io::Result<(OwnedHandle, u32)> {
        use windows_sys::Win32::System::Threading::{
            CREATE_SUSPENDED, ResumeThread, TerminateProcess,
        };
        let (process, thread, id) = self.create(path, setting, CREATE_SUSPENDED)?;
        let resumed = self.give_start_up_list(&process).and_then(|()| {
            // SAFETY: the first thread of the suspended worker, whose handle this call owns.
            if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
        if let Err(error) = resumed {
            // SAFETY: the handle of the worker this call made, which never ran.
            unsafe { TerminateProcess(process.as_raw_handle(), 1) };
            return Err(error);
        }
        drop(thread);
        let limited = limited_process(&process)?;
        Ok((limited, id))
    }

    /// Gives the token of the suspended worker `process` the start-up list as its default list,
    /// and checks that it reads back so.
    fn give_start_up_list(&self, process: &OwnedHandle) -> io::Result<()> {
        use windows_sys::Win32::Security::{TOKEN_ADJUST_DEFAULT, TOKEN_QUERY};
        use windows_sys::Win32::System::Threading::OpenProcessToken;
        let access = super::start_up_access(&sid_text(self.0)?);
        let mut token = ptr::null_mut();
        // SAFETY: the worker's full process handle, which the caller owns; the call writes the
        // token's handle, closed below.
        let opened = unsafe {
            OpenProcessToken(
                process.as_raw_handle(),
                TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
                &mut token,
            )
        } != 0;
        if !opened {
            return Err(io::Error::last_os_error());
        }
        let set = super::restrict_default(token, access.as_ptr());
        // SAFETY: closes the token's handle opened above, once.
        unsafe { CloseHandle(token) };
        if set {
            Ok(())
        } else {
            Err(io::Error::other(
                "the worker's token did not take its start-up access list",
            ))
        }
    }

    /// Makes the worker's process with `flags` beside the launcher's own. The process and its
    /// first thread get, from their creation, the access lists the worker later sets on itself:
    /// no other process of the user can open them in between and keep that handle.
    fn create(
        &self,
        path: &[u16],
        setting: &str,
        flags: u32,
    ) -> io::Result<(OwnedHandle, OwnedHandle, u32)> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::System::Threading::{
            CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DETACHED_PROCESS,
            EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, STARTUPINFOEXW,
        };
        let attributes = Attributes::new(self.0)?;
        let process_list = Descriptor::of(super::PROCESS_ACCESS)?;
        let thread_list = Descriptor::of(super::THREAD_ACCESS)?;
        let (process_attributes, thread_attributes) =
            (process_list.attributes(), thread_list.attributes());
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.list;
        let own = (crate::worker::WORKER, std::ffi::OsString::from(setting));
        let kept = SYSTEM_VARIABLES.map(|name| Some((name, std::env::var_os(name)?)));
        let mut variables: Vec<_> = kept.into_iter().flatten().chain([own]).collect();
        // Windows wants the block sorted by name, whatever the case of the letters.
        variables.sort_by_key(|(name, _)| name.to_ascii_uppercase());
        let mut environment: Vec<u16> = Vec::new();
        for (name, value) in &variables {
            environment.extend(name.encode_utf16().chain([u16::from(b'=')]));
            environment.extend(value.encode_wide().chain([0]));
        }
        environment.push(0);
        let mut command: Vec<u16> = [u16::from(b'"')]
            .into_iter()
            .chain(path[..path.len() - 1].iter().copied())
            .chain([u16::from(b'"'), 0])
            .collect();
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: every pointer is valid for the call: the NUL-terminated path, the command line,
        // which the call may change, the two security attributes, the environment block ending in
        // two NULs, and the startup information with its attribute list. No handle is inherited.
        let started = unsafe {
            CreateProcessW(
                path.as_ptr(),
                command.as_mut_ptr(),
                &process_attributes,
                &thread_attributes,
                0,
                EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_UNICODE_ENVIRONMENT
                    | DETACHED_PROCESS
                    | flags,
                environment.as_mut_ptr().cast(),
                ptr::null(),
                &startup.StartupInfo,
                &mut information,
            )
        } != 0;
        if !started {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateProcess returned two handles that nothing else owns.
        let (process, thread) = unsafe {
            (
                OwnedHandle::from_raw_handle(information.hProcess.cast()),
                OwnedHandle::from_raw_handle(information.hThread.cast()),
            )
        };
        Ok((process, thread, information.dwProcessId))
    }
}

/// Retain only the rights used to wait for and terminate the worker.
fn limited_process(process: &OwnedHandle) -> io::Result<OwnedHandle> {
    use windows_sys::Win32::Foundation::DuplicateHandle;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess,
        WaitForSingleObject,
    };
    let mut limited = ptr::null_mut();
    // SAFETY: both process pseudo handles name the caller. The source is owned throughout;
    // the new handle is noninheritable, with the explicit access mask.
    unsafe {
        let caller = GetCurrentProcess();
        if DuplicateHandle(
            caller,
            process.as_raw_handle().cast(),
            caller,
            &mut limited,
            PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
            0,
            0,
        ) == 0
        {
            let error = io::Error::last_os_error();
            if TerminateProcess(process.as_raw_handle().cast(), 1) != 0 {
                WaitForSingleObject(process.as_raw_handle().cast(), 1000);
            }
            return Err(error);
        }
        Ok(OwnedHandle::from_raw_handle(limited.cast()))
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // SAFETY: frees the SID the profile call allocated, once.
        unsafe { windows_sys::Win32::Security::FreeSid(self.0) };
    }
}

/// The attribute list of a worker's start, deleted when dropped, which happens only for a list
/// that was initialized. The worker gets its AppContainer, of the less privileged kind, without
/// ALL APPLICATION PACKAGES, and from its creation the mitigation policies it would otherwise set
/// on itself after its start-up code: no child process, no extension points, no unknown image.
/// Its job it still makes itself: Windows nests no job with desktop limits in another, so one
/// given at creation would fail the start of a launcher that runs in any job.
struct Attributes {
    list: windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST,
    _memory: Vec<u64>,
    _values: Box<Values>,
}

/// What the attributes point to, which lives as long as the list.
struct Values {
    capabilities: windows_sys::Win32::Security::SECURITY_CAPABILITIES,
    packages: u32,
    mitigations: u64,
    children: u32,
}

/// How many attributes a worker's start has.
const ATTRIBUTES: u32 = 4;

/// PROCESS_CREATION_MITIGATION_POLICY_*_ALWAYS_ON of winbase.h for the policies the worker also
/// sets on itself: extension points disabled (bit 32), and no remote image (52), none with a low
/// label (56), System32's copy first (60).
const CREATION_MITIGATIONS: u64 = (1 << 32) | (1 << 52) | (1 << 56) | (1 << 60);

impl Attributes {
    fn new(container: PSID) -> io::Result<Self> {
        use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
        use windows_sys::Win32::System::Threading::{
            InitializeProcThreadAttributeList,
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
            PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, UpdateProcThreadAttribute,
        };
        use windows_sys::Win32::System::WindowsProgramming::{
            PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
            PROCESS_CREATION_CHILD_PROCESS_RESTRICTED,
        };
        let values = Box::new(Values {
            capabilities: SECURITY_CAPABILITIES {
                AppContainerSid: container,
                Capabilities: ptr::null_mut(),
                CapabilityCount: 0,
                Reserved: 0,
            },
            packages: PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
            mitigations: CREATION_MITIGATIONS,
            children: PROCESS_CREATION_CHILD_PROCESS_RESTRICTED,
        });
        let mut size = 0;
        // SAFETY: with no list, the call only answers the size of a list of the attributes.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), ATTRIBUTES, 0, &mut size) };
        let mut memory = vec![0_u64; size.div_ceil(8)];
        let list = memory.as_mut_ptr().cast();
        // SAFETY: the memory has the size the first call asked for.
        if unsafe { InitializeProcThreadAttributeList(list, ATTRIBUTES, 0, &mut size) } == 0 {
            // Not initialized: there is nothing to delete.
            return Err(io::Error::last_os_error());
        }
        let attributes = Self {
            list,
            _memory: memory,
            _values: values,
        };
        let value = &*attributes._values;
        let entries: [(u32, *const core::ffi::c_void, usize); ATTRIBUTES as usize] = [
            (
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                (&raw const value.capabilities).cast(),
                size_of::<SECURITY_CAPABILITIES>(),
            ),
            (
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                (&raw const value.packages).cast(),
                size_of::<u32>(),
            ),
            (
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                (&raw const value.mitigations).cast(),
                size_of::<u64>(),
            ),
            (
                PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                (&raw const value.children).cast(),
                size_of::<u32>(),
            ),
        ];
        for (attribute, pointer, length) in entries {
            // SAFETY: the list is initialized with room for every attribute; each points into
            // the boxed values, which live as long as the list.
            let updated = unsafe {
                UpdateProcThreadAttribute(
                    list,
                    0,
                    attribute as usize,
                    pointer,
                    length,
                    ptr::null_mut(),
                    ptr::null(),
                )
            } != 0;
            if !updated {
                // The error of the update, read before the drop of the list replaces it.
                return Err(io::Error::last_os_error());
            }
        }
        Ok(attributes)
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: deletes a list that `new` initialized, once.
        unsafe { windows_sys::Win32::System::Threading::DeleteProcThreadAttributeList(self.list) };
    }
}

/// A worker is started without one handle of its parent's. What the program opened itself by
/// the time it serves is not listed here.
pub(crate) fn starts_clean() -> bool {
    true
}

/// A worker is started without a console.
pub(crate) fn leave_terminal() -> bool {
    true
}

/// The worker's pipe, its input and its output in one. Dropping it closes the pipe: the parent
/// sees the end at once, however long the worker lives on.
pub(crate) struct WorkerStreams(File);

impl WorkerStreams {
    pub(crate) fn enter(&mut self, options: crate::Options) -> io::Result<crate::Isolation> {
        super::enter_with_census(options, |phase| {
            self.write_all(&phase.tag())?;
            crate::worker::read_roster(self, super::threads::MAX_THREADS)
        })
    }
}

impl io::Read for WorkerStreams {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read(buffer)
    }
}

impl io::Write for WorkerStreams {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// Opens the worker's pipe by the name its parent gave it. A name that is no worker's pipe is
/// refused.
pub(crate) fn worker_streams(channel: &str) -> io::Result<WorkerStreams> {
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    let (name, nonce) = channel.split_once(',').ok_or(io::ErrorKind::InvalidData)?;
    let expected = u128::from_str_radix(nonce, 16).map_err(|_| io::ErrorKind::InvalidData)?;
    let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let deadline = std::time::Instant::now() + PATIENCE;
    let pipe = loop {
        // SAFETY: the name is NUL-terminated; the call returns a new handle or
        // INVALID_HANDLE_VALUE. The other end may learn who this process is, and no more.
        let pipe = unsafe {
            CreateFileW(
                name.as_ptr(),
                CLIENT_ACCESS,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if pipe != INVALID_HANDLE_VALUE {
            break pipe;
        }
        // Busy: another process holds the pipe until the parent puts it off.
        let error = io::Error::last_os_error();
        let busy = error.raw_os_error() == i32::try_from(ERROR_PIPE_BUSY).ok();
        if !busy || std::time::Instant::now() >= deadline {
            return Err(error);
        }
        std::thread::sleep(crate::os::STEP);
    };
    // SAFETY: the handle was just opened and nothing else owns it.
    let mut file = unsafe { File::from_raw_handle(pipe.cast()) };
    verify_server(&file)?;
    verify_nonce(&mut file, expected)?;
    Ok(WorkerStreams(file))
}

/// Bind the server to this particular launch even if the original parent exits and
/// Windows reuses its PID. The nonce is independent of the publicly visible pipe name.
fn verify_nonce(input: &mut impl Read, expected: u128) -> io::Result<()> {
    let mut received = [0; 16];
    input.read_exact(&mut received)?;
    if u128::from_le_bytes(received) == expected {
        Ok(())
    } else {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

/// The launcher supplies security evidence. Its pipe must still belong to the process
/// that created this worker. No access to the parent's process or tokens is needed.
fn verify_server(pipe: &File) -> io::Result<()> {
    use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, PROCESS_BASIC_INFORMATION};
    let mut basic = PROCESS_BASIC_INFORMATION::default();
    let mut size = 0;
    let mut server = 0;
    // SAFETY: query only this process through its pseudo-handle, and the already-open
    // client handle. Both output buffers have the types and sizes required by the APIs.
    let verified = unsafe {
        NtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessBasicInformation,
            (&raw mut basic).cast(),
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut size,
        ) == 0
            && size as usize == size_of::<PROCESS_BASIC_INFORMATION>()
            && GetNamedPipeServerProcessId(pipe.as_raw_handle().cast(), &mut server) != 0
            && server != 0
            && server as usize == basic.InheritedFromUniqueProcessId
    };
    if verified {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "worker pipe server does not match its launcher",
        ))
    }
}

#[cfg(test)]
mod handle_tests {
    use super::{limited_process, verify_nonce};

    /// The worker's process and first thread hold their restricted lists before the worker runs
    /// one instruction (it stays suspended here).
    #[test]
    fn a_worker_is_made_with_its_access_lists() -> std::io::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, GetLastError};
        use windows_sys::Win32::System::Threading::{
            CREATE_SUSPENDED, OpenProcess, PROCESS_VM_READ, TerminateProcess,
        };
        // An enabled debug privilege would open the worker whatever its list. It goes before the
        // worker is made, so that a failed check leaves no suspended process behind.
        drop_debug_privilege();
        let program = std::env::current_exe()?;
        let path: Vec<u16> = program.as_os_str().encode_wide().chain([0]).collect();
        let container = super::Container::of(&path)?;
        let (process, thread, id) = container.create(&path, "0,0,none,0", CREATE_SUSPENDED)?;
        let start_up = container.give_start_up_list(&process);
        let less_privileged = less_privileged(&process);
        let mitigated = mitigated_from_creation(&process);
        let holds = |object: &std::os::windows::io::OwnedHandle, access| {
            super::super::with_access_list(access, |wanted| {
                super::super::access_reads_back(object.as_raw_handle().cast(), wanted)
            })
        };
        let process_holds = holds(&process, super::super::PROCESS_ACCESS);
        let thread_holds = holds(&thread, super::super::THREAD_ACCESS);
        // Another process of the same user, here this test opening it by number, cannot read its
        // memory.
        // SAFETY: asks for a new handle by number and closes one it gets.
        let (opened, error) = unsafe {
            let opened = OpenProcess(PROCESS_VM_READ, 0, id);
            let error = GetLastError();
            if !opened.is_null() {
                CloseHandle(opened);
            }
            (!opened.is_null(), error)
        };
        // SAFETY: ends the suspended process this test made, through its own handle.
        unsafe { TerminateProcess(process.as_raw_handle().cast(), 1) };
        assert!(
            process_holds,
            "the process was made without its access list"
        );
        assert!(
            thread_holds,
            "the first thread was made without its access list"
        );
        assert!(
            !opened && error == ERROR_ACCESS_DENIED,
            "another process of the user could open the worker's memory (opened {opened}, error \
             {error})"
        );
        assert!(
            start_up.is_ok(),
            "the worker's token did not take its start-up list: {start_up:?}"
        );
        assert!(
            less_privileged,
            "the worker is not in a less privileged AppContainer"
        );
        assert!(
            mitigated,
            "the worker was made without its mitigation policies"
        );
        Ok(())
    }

    /// Whether the token of the worker `process` is of a less privileged AppContainer. False when
    /// it cannot be read, so that the caller still ends the worker before it asserts.
    fn less_privileged(process: &std::os::windows::io::OwnedHandle) -> bool {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::Security::{
            GetTokenInformation, TOKEN_QUERY, TokenIsLessPrivilegedAppContainer,
        };
        use windows_sys::Win32::System::Threading::OpenProcessToken;
        let mut token = std::ptr::null_mut();
        // SAFETY: the worker's full process handle; the call writes the token's handle, closed
        // below.
        if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
            return false;
        }
        let (mut value, mut length) = (0_u32, 0);
        // SAFETY: the call writes at most one DWORD into `value`, and the length it needed.
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenIsLessPrivilegedAppContainer,
                (&raw mut value).cast(),
                size_of::<u32>() as u32,
                &mut length,
            )
        } != 0;
        // SAFETY: closes the token's handle opened above, once.
        unsafe { CloseHandle(token) };
        read && value != 0
    }

    /// Whether the worker `process` has, from its creation, the mitigation policies it would set
    /// on itself: no extension points, images only from known places, no child process.
    fn mitigated_from_creation(process: &std::os::windows::io::OwnedHandle) -> bool {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::{
            GetProcessMitigationPolicy, PROCESS_MITIGATION_POLICY, ProcessChildProcessPolicy,
            ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
        };
        let has = |policy: PROCESS_MITIGATION_POLICY, flags: u32| {
            let mut read = 0_u32;
            // SAFETY: the policy writes one DWORD; the handle is the worker's full one.
            let got = unsafe {
                GetProcessMitigationPolicy(
                    process.as_raw_handle(),
                    policy,
                    (&raw mut read).cast(),
                    size_of::<u32>(),
                )
            } != 0;
            got && read & flags == flags
        };
        has(
            ProcessExtensionPointDisablePolicy,
            super::super::NO_EXTENSION_POINTS,
        ) && has(ProcessImageLoadPolicy, super::super::KNOWN_IMAGES)
            && has(ProcessChildProcessPolicy, super::super::NO_CHILD_PROCESSES)
    }

    /// Removes the debug privilege from the token of this test process, as the isolation tests
    /// do: a program that holds it opens any process whatever its access list, and the test
    /// runner of a CI machine may hold it. It stays removed from then on, for this process and
    /// the children it starts.
    fn drop_debug_privilege() {
        use std::ptr;
        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, GetLastError, LUID,
        };
        use windows_sys::Win32::Security::{
            AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_DEBUG_NAME,
            SE_PRIVILEGE_REMOVED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let mut token = ptr::null_mut();
        // SAFETY: opens the token of this process to change its privileges; closed below.
        let opened =
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) };
        assert_ne!(opened, 0);
        let mut privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: LUID::default(),
                Attributes: SE_PRIVILEGE_REMOVED,
            }],
        };
        // SAFETY: the name is NUL-terminated; the call writes the privilege's number.
        let found = unsafe {
            LookupPrivilegeValueW(
                ptr::null(),
                SE_DEBUG_NAME,
                &mut privileges.Privileges[0].Luid,
            )
        };
        assert_ne!(found, 0);
        // SAFETY: the list lives for the call, which is asked for no earlier state.
        let adjusted = unsafe {
            AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut())
        };
        // SAFETY: reads this thread's last error, which AdjustTokenPrivileges set.
        let error = unsafe { GetLastError() };
        // SAFETY: closes the token opened above, once.
        unsafe { CloseHandle(token) };
        // ERROR_NOT_ALL_ASSIGNED: the token does not hold the privilege.
        assert!(
            adjusted != 0 && matches!(error, ERROR_SUCCESS | ERROR_NOT_ALL_ASSIGNED),
            "error {error}"
        );
    }

    /// The clock decides a deadline: work that ends in time leaves the worker running; work that
    /// ends past it fails with `TimedOut` and ends the worker. A waiting process stands in for it.
    #[test]
    fn a_deadline_goes_by_the_clock() -> std::io::Result<()> {
        use std::time::{Duration, Instant};
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        let worker: std::os::windows::io::OwnedHandle = std::process::Command::new("cmd")
            .args(["/c", "ping -n 30 127.0.0.1 > nul"])
            .spawn()?
            .into();
        // SAFETY: waits on a handle this test owns, at most the time given.
        let state = |wait| unsafe { WaitForSingleObject(worker.as_raw_handle().cast(), wait) };
        let quick = super::within(
            &worker,
            Some(Instant::now() + Duration::from_secs(10)),
            || Ok(7),
        );
        assert_eq!(quick?, 7);
        assert_eq!(
            state(0),
            WAIT_TIMEOUT,
            "a worker whose work ended in time was ended"
        );
        let slow = super::within(
            &worker,
            Some(Instant::now() + Duration::from_millis(100)),
            || {
                std::thread::sleep(Duration::from_millis(400));
                Ok(())
            },
        );
        assert_eq!(
            slow.map_err(|error| error.kind()),
            Err(std::io::ErrorKind::TimedOut)
        );
        assert_eq!(state(5000), WAIT_OBJECT_0, "the late worker was not ended");
        Ok(())
    }

    #[test]
    fn a_launch_nonce_is_required_before_the_first_roster() {
        let nonce = 1234u128;
        assert!(verify_nonce(&mut nonce.to_le_bytes().as_slice(), nonce).is_ok());
        assert!(verify_nonce(&mut (nonce + 1).to_le_bytes().as_slice(), nonce).is_err());
        assert!(verify_nonce(&mut nonce.to_le_bytes()[..15].as_ref(), nonce).is_err());
    }

    use std::io;
    use std::os::windows::io::{AsHandle, AsRawHandle};
    use std::process::{Command, Stdio};
    use windows_sys::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, GetLastError, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        GetProcessId, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, WaitForSingleObject,
    };
    use windows_sys::Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION;

    #[test]
    fn retained_handle_has_exactly_the_two_worker_lifecycle_rights() -> io::Result<()> {
        let mut child = Command::new(std::env::current_exe()?)
            .arg("--list")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let full = child.as_handle().try_clone_to_owned()?;
        let limited = limited_process(&full)?;
        let handle = limited.as_raw_handle().cast();
        // SAFETY: the process handle is alive for this metadata query.
        let id = unsafe { GetProcessId(full.as_raw_handle().cast()) };
        assert_eq!(id, child.id());
        // SAFETY: the duplicated handle is valid. Access denial is checked immediately.
        let (id, error) = unsafe { (GetProcessId(handle), GetLastError()) };
        assert_eq!(id, 0);
        assert_eq!(error, ERROR_ACCESS_DENIED);

        let mut basic = PUBLIC_OBJECT_BASIC_INFORMATION::default();
        let mut bytes = 0;
        // SAFETY: the handle is live and both output buffers fit their documented types.
        let result = unsafe {
            NtQueryObject(
                handle,
                ObjectBasicInformation,
                (&raw mut basic).cast(),
                std::mem::size_of_val(&basic) as u32,
                &mut bytes,
            )
        };
        assert!(result >= 0, "NtQueryObject status {result:#x}");
        assert_eq!(basic.GrantedAccess, PROCESS_TERMINATE | PROCESS_SYNCHRONIZE);

        assert!(child.wait()?.success());
        // SAFETY: the owned process handle remains valid after its child has finished.
        assert_eq!(unsafe { WaitForSingleObject(handle, 0) }, WAIT_OBJECT_0);
        Ok(())
    }
}
