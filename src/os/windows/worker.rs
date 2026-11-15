//! The worker process on Windows: started in an AppContainer without capabilities, with its
//! two pipes as the only handles it inherits.

use std::io;
use std::mem::size_of;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};

/// The parent's end of a worker: pipes to its standard input and from its standard output, and
/// the process.
pub(crate) struct WorkerProcess {
    pub(crate) to: Option<std::fs::File>,
    pub(crate) from: Option<std::fs::File>,
    process: std::os::windows::io::OwnedHandle,
}

impl WorkerProcess {
    /// Starts this program again in its own AppContainer: no capabilities, no console, an environment
    /// with only the worker variable, set to `setting`, and only its two pipes inherited. The
    /// program file must be readable by app containers (Program Files is), or Windows refuses to
    /// start it. A worker on the terminal is not offered here.
    pub(crate) fn start(setting: &str, terminal: bool) -> io::Result<Self> {
        use std::os::windows::ffi::OsStrExt;
        if terminal {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let program = std::env::current_exe()?;
        let path: Vec<u16> = program.as_os_str().encode_wide().chain([0]).collect();
        let container = Container::of(&path)?;
        let pipes = Pipes::new()?;
        let process = container.start(&path, &pipes, setting)?;
        Ok(Self {
            to: Some(std::fs::File::from(pipes.parent_in)),
            from: Some(std::fs::File::from(pipes.parent_out)),
            process,
        })
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

/// The SID of the program's AppContainer, freed when dropped.
struct Container(windows_sys::Win32::Security::PSID);

/// Held while the worker's ends of the pipes can be inherited, so that two workers starting at
/// once never get each other's ends. Other code of the program that starts a process with
/// handle inheritance in that moment is beyond this lock.
static LAUNCHING: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    /// Starts the program at `path` in this AppContainer, without capabilities, its standard input
    /// and output the child's ends of `pipes`, which are the only handles it inherits, and with the
    /// worker's variable alone in its environment. The child's ends can be inherited only for the
    /// length of this call, under [`LAUNCHING`].
    fn start(
        &self,
        path: &[u16],
        pipes: &Pipes,
        setting: &str,
    ) -> io::Result<std::os::windows::io::OwnedHandle> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::Threading::{
            CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
            EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOEXW,
        };
        let handles: [HANDLE; 2] = [
            pipes.child_in.as_raw_handle().cast(),
            pipes.child_out.as_raw_handle().cast(),
        ];
        let attributes = Attributes::new(self.0, &handles)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
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
        let _launching = LAUNCHING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let inheritable = pipes.inherit(true);
        // SAFETY: every pointer is valid for the call: the NUL-terminated path, the command line,
        // which the call may change, the environment block ending in two NULs, and the startup
        // information with its attribute list.
        let started = inheritable.is_ok()
            && unsafe {
                CreateProcessW(
                    path.as_ptr(),
                    command.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    1,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                    environment.as_mut_ptr().cast(),
                    ptr::null(),
                    &startup.StartupInfo,
                    &mut information,
                )
            } != 0;
        let error = io::Error::last_os_error();
        let _ = pipes.inherit(false);
        inheritable?;
        if !started {
            return Err(error);
        }
        // SAFETY: the process and thread handles were just made and nothing else owns them.
        unsafe {
            CloseHandle(information.hThread);
            Ok(OwnedHandle::from_raw_handle(information.hProcess.cast()))
        }
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // SAFETY: frees the SID the profile call allocated, once.
        unsafe { windows_sys::Win32::Security::FreeSid(self.0) };
    }
}

/// The attribute list of a worker's start: its AppContainer, and the two handles it may inherit.
/// Deleted when dropped, which happens only for a list that was initialized.
struct Attributes {
    list: windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST,
    _memory: Vec<u64>,
    _capabilities: Box<windows_sys::Win32::Security::SECURITY_CAPABILITIES>,
}

impl Attributes {
    fn new(
        container: windows_sys::Win32::Security::PSID,
        handles: &[HANDLE; 2],
    ) -> io::Result<Self> {
        use windows_sys::Win32::Security::SECURITY_CAPABILITIES;
        use windows_sys::Win32::System::Threading::{
            InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, UpdateProcThreadAttribute,
        };
        let capabilities = Box::new(SECURITY_CAPABILITIES {
            AppContainerSid: container,
            Capabilities: ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        });
        let mut size = 0;
        // SAFETY: with no list, the call only answers the size of a list of two attributes.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 2, 0, &mut size) };
        let mut memory = vec![0_u64; size.div_ceil(8)];
        let list = memory.as_mut_ptr().cast();
        // SAFETY: the memory has the size the first call asked for.
        if unsafe { InitializeProcThreadAttributeList(list, 2, 0, &mut size) } == 0 {
            // Not initialized: there is nothing to delete.
            return Err(io::Error::last_os_error());
        }
        let attributes = Self {
            list,
            _memory: memory,
            _capabilities: capabilities,
        };
        // SAFETY: the list is initialized with room for two attributes; each points to a value
        // that lives as long as the list: the boxed capabilities, and the caller's handles.
        let updated = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                (&raw const *attributes._capabilities).cast(),
                size_of::<SECURITY_CAPABILITIES>(),
                ptr::null_mut(),
                ptr::null(),
            ) != 0
                && UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_ptr().cast(),
                    size_of::<[HANDLE; 2]>(),
                    ptr::null_mut(),
                    ptr::null(),
                ) != 0
        };
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

/// The two pipes of a worker. No end can be inherited, except the child's two for the length of
/// the worker's own start.
struct Pipes {
    child_in: std::os::windows::io::OwnedHandle,
    parent_in: std::os::windows::io::OwnedHandle,
    parent_out: std::os::windows::io::OwnedHandle,
    child_out: std::os::windows::io::OwnedHandle,
}

impl Pipes {
    fn new() -> io::Result<Self> {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::Pipes::CreatePipe;
        let pipe = || -> io::Result<(OwnedHandle, OwnedHandle)> {
            let (mut read, mut write) = (ptr::null_mut(), ptr::null_mut());
            // SAFETY: the call writes two new handles, which nothing else owns; without security
            // attributes no process inherits them.
            if unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: as above; the owners close them when dropped.
            Ok(unsafe {
                (
                    OwnedHandle::from_raw_handle(read.cast()),
                    OwnedHandle::from_raw_handle(write.cast()),
                )
            })
        };
        let (child_in, parent_in) = pipe()?;
        let (parent_out, child_out) = pipe()?;
        Ok(Self {
            child_in,
            parent_in,
            parent_out,
            child_out,
        })
    }

    /// Lets the child's two ends be inherited, or not.
    fn inherit(&self, inherit: bool) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
        let flag = if inherit { HANDLE_FLAG_INHERIT } else { 0 };
        for end in [&self.child_in, &self.child_out] {
            // SAFETY: changes only whether a child inherits the handle.
            if unsafe {
                SetHandleInformation(end.as_raw_handle().cast(), HANDLE_FLAG_INHERIT, flag)
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

/// A worker inherits no handle but its pipes: nothing to close.
pub(crate) fn close_inherited() -> bool {
    true
}

/// A worker is started without a console.
pub(crate) fn leave_terminal() -> bool {
    true
}

/// The worker's standard input and output, unbuffered; they stay open when dropped.
pub(crate) fn worker_streams() -> (
    std::mem::ManuallyDrop<std::fs::File>,
    std::mem::ManuallyDrop<std::fs::File>,
) {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::System::Console::STD_INPUT_HANDLE;
    // SAFETY: the standard handles are the pipes the parent made, open for the whole process;
    // `ManuallyDrop` never closes them.
    unsafe {
        (
            std::mem::ManuallyDrop::new(std::fs::File::from_raw_handle(
                GetStdHandle(STD_INPUT_HANDLE).cast(),
            )),
            std::mem::ManuallyDrop::new(std::fs::File::from_raw_handle(
                GetStdHandle(STD_OUTPUT_HANDLE).cast(),
            )),
        )
    }
}
