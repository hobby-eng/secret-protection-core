//! The worker process on Windows: started in an AppContainer without capabilities, and without
//! one handle of its parent's. The two talk through a named pipe that the worker opens by name.

use std::fs::File;
use std::io;
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
const PIPE_PREFIX: &str = r"\\.\pipe\secret-protection-core.";
/// The pipe's buffers, each way.
const PIPE_BUFFER: u32 = 64 << 10;
/// How long a worker keeps trying its pipe while another process holds it.
const PATIENCE: Duration = Duration::from_secs(1);

/// The parent's end of a worker: its pipe, as one handle to write to and one to read from, and
/// the process.
pub(crate) struct WorkerProcess {
    pub(crate) to: Option<File>,
    pub(crate) from: Option<File>,
    process: OwnedHandle,
}

impl WorkerProcess {
    /// Starts this program again in its own AppContainer: no capabilities, no console, no handle
    /// inherited, and an environment with only the worker variable, set to `setting` and the
    /// name of its pipe. The program file must be readable by app containers (Program Files
    /// is), or Windows refuses to start it. A worker on the terminal is not offered here.
    pub(crate) fn start(setting: &str, terminal: bool) -> io::Result<Self> {
        use std::os::windows::ffi::OsStrExt;
        if terminal {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let program = std::env::current_exe()?;
        let path: Vec<u16> = program.as_os_str().encode_wide().chain([0]).collect();
        let container = Container::of(&path)?;
        let (pipe, name) = listen(&container)?;
        let (process, id) = container.start(&path, &format!("{setting},{name}"))?;
        let mut worker = Self {
            to: None,
            from: None,
            process,
        };
        let process: HANDLE = worker.process.as_raw_handle().cast();
        match accept(&pipe, process, id).and_then(|()| pipe.try_clone()) {
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
        // SAFETY: waits on, and if need be ends, the process whose handle this value owns.
        unsafe {
            WaitForSingleObject(process, grace) == WAIT_OBJECT_0
                || (TerminateProcess(process, 1) != 0
                    && WaitForSingleObject(process, grace) == WAIT_OBJECT_0)
        }
    }
}

/// Makes the pipe of one worker and returns it with its name. Its access list takes this user,
/// in `container` or in none: Windows gives an app container what the user's entry and the
/// container's both give. It has one instance, so one process holds it at a time, and none
/// inherits it.
fn listen(container: &Container) -> io::Result<(OwnedHandle, String)> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE,
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
        return Err(io::Error::other("Windows gave no random name for the pipe"));
    }
    let name = format!("{PIPE_PREFIX}{:032x}", u128::from_le_bytes(random));
    // The user and the container may read and write; the owner's own rights end at reading
    // this list; the low label lets a process of low integrity write.
    let access = format!(
        "D:P(A;;{CLIENT_ACCESS:#x};;;{})(A;;{CLIENT_ACCESS:#x};;;{})(A;;RC;;;OW)S:(ML;;NW;;;LW)",
        user()?,
        sid_text(container.0)?
    );
    let access: Vec<u16> = access.encode_utf16().chain([0]).collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: the string is NUL-terminated; the call allocates the descriptor, freed below.
    let made = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            access.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } != 0;
    if !made {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
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
    // SAFETY: frees the descriptor the conversion allocated, once, after its last use.
    unsafe { LocalFree(descriptor) };
    if pipe == INVALID_HANDLE_VALUE {
        return Err(error);
    }
    // SAFETY: the handle was just made and nothing else owns it.
    Ok((unsafe { OwnedHandle::from_raw_handle(pipe.cast()) }, name))
}

/// Waits for the worker to open `pipe` and takes no one else: the process at the other end must
/// be number `id`. Another process that opens it first is put off, and the pipe listens again.
/// An error when the worker ends first. From then on the pipe waits for reads and writes.
fn accept(pipe: &OwnedHandle, process: HANDLE, id: u32) -> io::Result<()> {
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
        // SAFETY: asks, without waiting, whether the worker has ended.
        let ended = unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0;
        if ended || !(listens || error == ERROR_PIPE_LISTENING) {
            return Err(io::Error::other("the worker did not open its pipe"));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let waits = PIPE_READMODE_BYTE | PIPE_WAIT;
    // SAFETY: the call reads one mode word, which lives for the call.
    if unsafe { SetNamedPipeHandleState(pipe, &waits, ptr::null(), ptr::null()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl WorkerProcess {
    /// The handle of a worker left behind is closed with this value: nothing to take off a list.
    pub(crate) fn reap(&mut self) {}
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
fn sid_text(sid: PSID) -> io::Result<String> {
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
    /// handle of this process's and without standard streams, the worker's variable alone in
    /// its environment. Returns the process and its number.
    fn start(&self, path: &[u16], setting: &str) -> io::Result<(OwnedHandle, u32)> {
        use windows_sys::Win32::System::Threading::{
            CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
            EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, STARTUPINFOEXW,
        };
        let attributes = Attributes::new(self.0)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.list;
        let mut environment: Vec<u16> = format!("{}={setting}", crate::worker::WORKER)
            .encode_utf16()
            .chain([0, 0])
            .collect();
        let mut command: Vec<u16> = [u16::from(b'"')]
            .into_iter()
            .chain(path[..path.len() - 1].iter().copied())
            .chain([u16::from(b'"'), 0])
            .collect();
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: every pointer is valid for the call: the NUL-terminated path, the command line,
        // which the call may change, the environment block ending in two NULs, and the startup
        // information with its attribute list. No handle is inherited.
        let started = unsafe {
            CreateProcessW(
                path.as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                environment.as_mut_ptr().cast(),
                ptr::null(),
                &startup.StartupInfo,
                &mut information,
            )
        } != 0;
        if !started {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the process and thread handles were just made and nothing else owns them.
        unsafe {
            CloseHandle(information.hThread);
            Ok((
                OwnedHandle::from_raw_handle(information.hProcess.cast()),
                information.dwProcessId,
            ))
        }
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // SAFETY: frees the SID the profile call allocated, once.
        unsafe { windows_sys::Win32::Security::FreeSid(self.0) };
    }
}

/// The attribute list of a worker's start: its AppContainer. Deleted when dropped, which
/// happens only for a list that was initialized.
struct Attributes {
    list: windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST,
    _memory: Vec<u64>,
    _capabilities: Box<windows_sys::Win32::Security::SECURITY_CAPABILITIES>,
}

impl Attributes {
    fn new(container: PSID) -> io::Result<Self> {
        use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
        use windows_sys::Win32::System::Threading::{
            InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            UpdateProcThreadAttribute,
        };
        let capabilities = Box::new(SECURITY_CAPABILITIES {
            AppContainerSid: container,
            Capabilities: ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        });
        let mut size = 0;
        // SAFETY: with no list, the call only answers the size of a list of one attribute.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size) };
        let mut memory = vec![0_u64; size.div_ceil(8)];
        let list = memory.as_mut_ptr().cast();
        // SAFETY: the memory has the size the first call asked for.
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
            // Not initialized: there is nothing to delete.
            return Err(io::Error::last_os_error());
        }
        let attributes = Self {
            list,
            _memory: memory,
            _capabilities: capabilities,
        };
        // SAFETY: the list is initialized with room for one attribute, which points to the boxed
        // capabilities: they live as long as the list.
        let updated = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                (&raw const *attributes._capabilities).cast(),
                size_of::<SECURITY_CAPABILITIES>(),
                ptr::null_mut(),
                ptr::null(),
            )
        } != 0;
        if updated {
            Ok(attributes)
        } else {
            // The error of the update, read before the drop of the list replaces it.
            Err(io::Error::last_os_error())
        }
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
    let digits = channel.strip_prefix(PIPE_PREFIX).unwrap_or_default();
    if digits.len() != 32 || !digits.bytes().all(|digit| digit.is_ascii_hexdigit()) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let name: Vec<u16> = channel.encode_utf16().chain([0]).collect();
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
        std::thread::sleep(Duration::from_millis(2));
    };
    // SAFETY: the handle was just opened and nothing else owns it.
    Ok(WorkerStreams(unsafe { File::from_raw_handle(pipe.cast()) }))
}
