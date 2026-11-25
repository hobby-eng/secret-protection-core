//! The terminal of a hidden line on Unix: its echo, its own line editing and its signal keys off,
//! checked by reading the settings back, and the settings it had restored after. Only descriptors
//! the process holds are used, as a worker isolated from opening files has them.
#![allow(
    unsafe_code,
    reason = "isatty, fcntl, fstat, tcgetattr, tcsetattr, read and write are foreign functions"
)]

use std::io;
use std::os::fd::RawFd;

use zeroize::Zeroizing;

/// What a hidden line switches off in the local modes: echo, the terminal's own line editing, and
/// Ctrl+C, Ctrl+Z and Ctrl+\ as signals, so that every way out of the reading restores it.
const LOCAL_OFF: libc::tcflag_t =
    libc::ECHO | libc::ECHONL | libc::ICANON | libc::IEXTEN | libc::ISIG;

/// What it switches off in the input modes: Ctrl+C on a break, and what would change or lose a
/// typed key: Ctrl+S and Ctrl+Q as flow control, a dropped carriage return (Enter), and the
/// eighth bit of a byte, which UTF-8 needs.
const INPUT_OFF: libc::tcflag_t = libc::BRKINT | libc::IXON | libc::IGNCR | libc::ISTRIP;

/// Local-mode bits the terminal changes by itself, which are no settings to put back: PENDIN,
/// which macOS sets when line editing comes back on, and FLUSHO, which Ctrl+O switches there and
/// which drops all output while it is on.
const LOCAL_STATE: libc::tcflag_t = libc::PENDIN | libc::FLUSHO;

/// The most bytes a drain reads and drops: the input left before and after a reading, such as the
/// rest of a pasted text.
const DRAINED: usize = 64 << 10;

/// A terminal that shows nothing typed on it until [`HiddenTerminal::restore`] or the drop.
pub(crate) struct HiddenTerminal {
    /// Where the keys are read.
    input: RawFd,
    /// Where the prompt goes, when a terminal is open for writing.
    output: Option<RawFd>,
    original: libc::termios,
    /// The hidden settings with reads that do not wait, once they read back: a drain needs them,
    /// as a read in line-editing mode waits for a whole line.
    draining: Option<libc::termios>,
    restored: bool,
}

impl HiddenTerminal {
    /// The terminal of standard input, else of standard error, where a worker on the terminal has
    /// it, as far as it is open for reading; the prompt goes to the first of it, standard error
    /// and standard output that is the same terminal open for writing, else to any of them that
    /// is a terminal open for writing.
    pub(crate) fn open() -> io::Result<Self> {
        let input = [libc::STDIN_FILENO, libc::STDERR_FILENO]
            .into_iter()
            .find(|&descriptor| terminal_for(descriptor, libc::O_RDONLY))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "neither standard input nor standard error is a terminal to read",
                )
            })?;
        // The same terminal first; `/dev/tty`, as `< /dev/tty` gives it, is a device of its own.
        let writable = [input, libc::STDERR_FILENO, libc::STDOUT_FILENO]
            .into_iter()
            .filter(|&descriptor| terminal_for(descriptor, libc::O_WRONLY));
        let output = writable
            .clone()
            .find(|&descriptor| device(descriptor).is_some_and(|own| Some(own) == device(input)))
            .or_else(|| writable.clone().next());
        Self::on(input, output)
    }

    /// Switches the terminal on `input`, and refuses before reading anything unless the switch
    /// reads back. Break conditions on a serial line stop raising Ctrl+C too.
    pub(crate) fn on(input: RawFd, output: Option<RawFd>) -> io::Result<Self> {
        // A read that does not wait ends the line at once, and a drain cannot tell an empty queue
        // from a refusal: such an input is refused before anything changes.
        // SAFETY: fcntl with F_GETFL takes integers and only asks.
        let flags = unsafe { libc::fcntl(input, libc::F_GETFL) };
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::O_NONBLOCK != 0 {
            return Err(io::Error::other(
                "the terminal input is set not to wait for keys (O_NONBLOCK); nothing was read",
            ));
        }
        let mut original = settings(input)?;
        // Neither the hidden settings nor the restore sets the terminal's own bits again: FLUSHO
        // left on by a Ctrl+O would drop the prompt and all output after the reading.
        original.c_lflag &= !LOCAL_STATE;
        // From here on every way out restores the settings, whatever went through.
        let mut terminal = Self {
            input,
            output,
            original,
            draining: None,
            restored: false,
        };
        let mut hidden = original;
        hidden.c_lflag &= !LOCAL_OFF;
        hidden.c_iflag &= !INPUT_OFF;
        hidden.c_cc[libc::VMIN] = 0;
        hidden.c_cc[libc::VTIME] = 0;
        set(input, &hidden)?;
        // tcsetattr succeeds when any one of the changes was made: what reads back decides.
        switched(input, 0)?;
        // Keys waiting now, which the terminal may have shown or another program put in, are no
        // part of the line: read and dropped without waiting, those still on their way included.
        // A failed drain is not tried again on the way out, which would drop more than allowed.
        if !terminal.drain() {
            return Err(io::Error::other(
                "the input waiting before the reading could not be dropped; nothing was read",
            ));
        }
        terminal.draining = Some(hidden);
        hidden.c_cc[libc::VMIN] = 1;
        set(input, &hidden)?;
        switched(input, 1)?;
        Ok(terminal)
    }

    /// Writes `text` where the prompt goes, if anywhere.
    pub(crate) fn write(&mut self, text: &str) -> io::Result<()> {
        let Some(output) = self.output else {
            return Ok(());
        };
        let mut rest = text.as_bytes();
        while !rest.is_empty() {
            // SAFETY: write reads at most `rest.len()` bytes of `rest`, which lives for the call.
            let written = unsafe { libc::write(output, rest.as_ptr().cast(), rest.len()) };
            match usize::try_from(written) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(written) => rest = rest.get(written..).unwrap_or_default(),
                Err(_) if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(io::Error::last_os_error()),
            }
        }
        Ok(())
    }

    /// The next character typed, or `None` at the end of the input. Its bytes come one at a time
    /// into a buffer that is wiped when the character is whole.
    pub(crate) fn next_char(&mut self) -> io::Result<Option<char>> {
        let mut bytes = Zeroizing::new([0u8; 4]);
        let mut length = 0;
        loop {
            // SAFETY: read writes at most one byte, at `bytes[length]`, which lives for the call;
            // `length` stays below 4, as a fourth byte ends the loop whatever it makes.
            let read = unsafe { libc::read(self.input, bytes[length..].as_mut_ptr().cast(), 1) };
            match read {
                1 => length += 1,
                0 if length == 0 => return Ok(None),
                0 => return Err(not_text()),
                _ if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
                _ => return Err(io::Error::last_os_error()),
            }
            match std::str::from_utf8(&bytes[..length]) {
                Ok(text) => return Ok(text.chars().next()),
                Err(error) if error.error_len().is_none() && length < bytes.len() => {}
                Err(_) => return Err(not_text()),
            }
        }
    }

    /// Puts back the settings it found, once. What is left after Enter, such as the rest of a
    /// pasted text, is read and dropped first, under the hidden settings whatever another program
    /// set meanwhile, so that the next reader, often the shell, does not take it.
    /// The drain reads only under settings read back as not waiting, as a read in line-editing
    /// mode would wait for a line; the settings put back are read back too. Either failing is an
    /// error, after the settings were put back as far as the terminal took them.
    pub(crate) fn restore(&mut self) -> io::Result<()> {
        if std::mem::replace(&mut self.restored, true) {
            return Ok(());
        }
        let drained = self.draining.is_none_or(|draining| {
            set(self.input, &draining).is_ok() && switched(self.input, 0).is_ok() && self.drain()
        });
        set(self.input, &self.original)?;
        if !same(&settings(self.input)?, &self.original) {
            return Err(io::Error::other(
                "the terminal did not take back its settings",
            ));
        }
        if !drained {
            return Err(io::Error::other(
                "the input left after the reading could not be dropped",
            ));
        }
        Ok(())
    }

    /// Reads and drops up to [`DRAINED`] bytes, with reads that do not wait (VMIN 0), and says
    /// whether it reached the end of what was waiting. On Linux such a read first takes in the
    /// input still on its way to the terminal.
    fn drain(&mut self) -> bool {
        let mut sink = Zeroizing::new([0u8; 256]);
        let mut taken = 0_usize;
        loop {
            // SAFETY: read writes at most the buffer's length into it, which lives for the call.
            let read = unsafe { libc::read(self.input, sink.as_mut_ptr().cast(), sink.len()) };
            match usize::try_from(read) {
                Ok(0) => return true,
                // More than DRAINED: no end in sight.
                Ok(read) if taken + read > DRAINED => return false,
                Ok(read) => taken += read,
                Err(_) => match io::Error::last_os_error().kind() {
                    io::ErrorKind::Interrupted => {}
                    // Nothing waiting, where another program set the input not to wait.
                    io::ErrorKind::WouldBlock => return true,
                    _ => return false,
                },
            }
        }
    }
}

impl Drop for HiddenTerminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Refuses unless the terminal on `descriptor` reads back switched, with `minimum` as VMIN.
fn switched(descriptor: RawFd, minimum: libc::cc_t) -> io::Result<()> {
    let now = settings(descriptor)?;
    if now.c_lflag & LOCAL_OFF != 0
        || now.c_iflag & INPUT_OFF != 0
        || now.c_cc[libc::VMIN] != minimum
        || now.c_cc[libc::VTIME] != 0
    {
        return Err(io::Error::other(
            "the terminal did not take the hidden settings; nothing was read",
        ));
    }
    Ok(())
}

/// Whether `descriptor` is a terminal open for `access`, `O_RDONLY` to read or `O_WRONLY` to
/// write, or open for both; Linux's mode 3, for ioctls alone, is neither.
fn terminal_for(descriptor: RawFd, access: libc::c_int) -> bool {
    // SAFETY: isatty and fcntl with F_GETFL take integers and only ask.
    let (terminal, flags) = unsafe {
        (
            libc::isatty(descriptor) == 1,
            libc::fcntl(descriptor, libc::F_GETFL),
        )
    };
    let mode = flags & libc::O_ACCMODE;
    terminal && flags != -1 && (mode == access || mode == libc::O_RDWR)
}

/// Whether two settings agree in every field a terminal keeps: the modes, but for the bits it
/// changes by itself, the control keys and the speeds.
fn same(now: &libc::termios, then: &libc::termios) -> bool {
    // SAFETY: each call reads a speed out of a termios that lives for it.
    let kept = |settings: &libc::termios| unsafe {
        (
            (settings.c_iflag, settings.c_oflag, settings.c_cflag),
            settings.c_lflag & !LOCAL_STATE,
            settings.c_cc,
            (libc::cfgetispeed(settings), libc::cfgetospeed(settings)),
        )
    };
    kept(now) == kept(then)
}

/// The device behind `descriptor`, which tells one terminal from another.
fn device(descriptor: RawFd) -> Option<libc::dev_t> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat fills the stat when it succeeds.
    if unsafe { libc::fstat(descriptor, status.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: filled by the call that just succeeded.
    Some(unsafe { status.assume_init() }.st_rdev)
}

/// The settings of the terminal on `descriptor`.
fn settings(descriptor: RawFd) -> io::Result<libc::termios> {
    let mut settings = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: tcgetattr fills the termios when it succeeds.
    if unsafe { libc::tcgetattr(descriptor, settings.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: filled by the call that just succeeded.
    Ok(unsafe { settings.assume_init() })
}

/// Sets `settings` at once, again when a signal cut the call short.
fn set(descriptor: RawFd, settings: &libc::termios) -> io::Result<()> {
    loop {
        // SAFETY: a termios that lives for the call, for the terminal on `descriptor`.
        if unsafe { libc::tcsetattr(descriptor, libc::TCSANOW, settings) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn not_text() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the terminal sent bytes that are not UTF-8",
    )
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use crate::input::{LineEnd, edit};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /// A new pseudo-terminal: its controller, and the terminal end, which is no controlling
    /// terminal of this process.
    fn pseudo_terminal() -> (OwnedFd, OwnedFd) {
        // SAFETY: posix_openpt opens a new controller, owned once here; grantpt and unlockpt take
        // its descriptor; ptsname gives a NUL-terminated name that open reads at once.
        unsafe {
            let controller = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(controller >= 0);
            let controller = OwnedFd::from_raw_fd(controller);
            assert_eq!(libc::grantpt(controller.as_raw_fd()), 0);
            assert_eq!(libc::unlockpt(controller.as_raw_fd()), 0);
            let name = libc::ptsname(controller.as_raw_fd());
            assert!(!name.is_null());
            let terminal = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
            assert!(terminal >= 0);
            (controller, OwnedFd::from_raw_fd(terminal))
        }
    }

    /// Switches the terminal end, its prompt going to the same terminal.
    fn hidden(terminal: &OwnedFd) -> io::Result<HiddenTerminal> {
        HiddenTerminal::on(terminal.as_raw_fd(), Some(terminal.as_raw_fd()))
    }

    /// Writes `bytes` to `descriptor`, as keys typed on the terminal.
    fn type_keys(descriptor: &OwnedFd, bytes: &[u8]) {
        // SAFETY: write reads the bytes, which live for the call.
        let written =
            unsafe { libc::write(descriptor.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        assert_eq!(usize::try_from(written).ok(), Some(bytes.len()));
    }

    /// What the terminal showed: all the controller can read now.
    fn shown(controller: &OwnedFd) -> String {
        let descriptor = controller.as_raw_fd();
        // SAFETY: fcntl takes a descriptor and integers.
        unsafe {
            let flags = libc::fcntl(descriptor, libc::F_GETFL);
            libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let mut shown = Vec::new();
        let mut buffer = [0u8; 256];
        loop {
            // SAFETY: read writes at most the buffer's length into it.
            let read = unsafe { libc::read(descriptor, buffer.as_mut_ptr().cast(), buffer.len()) };
            match usize::try_from(read) {
                Ok(read) if read > 0 => shown.extend_from_slice(&buffer[..read]),
                _ => break,
            }
        }
        String::from_utf8_lossy(&shown).into_owned()
    }

    /// How many bytes the terminal holds to read.
    fn waiting(terminal: &OwnedFd) -> libc::c_int {
        let mut waiting: libc::c_int = -1;
        // SAFETY: FIONREAD writes the number of bytes waiting into an int that lives for the call.
        unsafe { libc::ioctl(terminal.as_raw_fd(), libc::FIONREAD, &raw mut waiting) };
        waiting
    }

    /// The keys come back as the line they make, the terminal shows none of them, and its
    /// settings are as before.
    #[test]
    fn a_hidden_line_is_read_unseen_and_the_terminal_restored() -> io::Result<()> {
        let (controller, terminal) = pseudo_terminal();
        // A break condition raises Ctrl+C before the reading, never during it, and output dropped
        // after a Ctrl+O (FLUSHO) shows again, the prompt first.
        let mut before = settings(terminal.as_raw_fd())?;
        before.c_iflag |= libc::BRKINT;
        before.c_lflag |= libc::FLUSHO;
        set(terminal.as_raw_fd(), &before)?;
        let mut hidden = hidden(&terminal)?;
        assert_eq!(settings(terminal.as_raw_fd())?.c_iflag & libc::BRKINT, 0);
        hidden.write("Password: ")?;
        // Backspace, a word, Ctrl+U, an arrow key, two-byte UTF-8, Enter.
        type_keys(&controller, "pass\x7fs w\x15\x1b[Asec\u{e9}t\r".as_bytes());
        let mut line = crate::SecretLine::with_capacity(64);
        assert_eq!(edit(&mut line, || hidden.next_char())?, LineEnd::Entered);
        hidden.restore()?;
        assert_eq!(line.as_str(), "sec\u{e9}t");
        let after = settings(terminal.as_raw_fd())?;
        assert_eq!(
            (after.c_lflag & !LOCAL_STATE, after.c_iflag, after.c_cc),
            (before.c_lflag & !LOCAL_STATE, before.c_iflag, before.c_cc)
        );
        assert_eq!(after.c_lflag & libc::FLUSHO, 0);
        assert_eq!(shown(&controller), "Password: ");
        Ok(())
    }

    /// Typed keys arrive whole: flow control, a dropped carriage return and a stripped eighth bit
    /// are off while it reads. An input set not to wait is refused before anything changes.
    #[test]
    fn keys_arrive_whole_and_an_input_that_does_not_wait_is_refused() -> io::Result<()> {
        let (controller, terminal) = pseudo_terminal();
        let mut before = settings(terminal.as_raw_fd())?;
        before.c_iflag |= libc::IXON | libc::IGNCR | libc::ISTRIP;
        set(terminal.as_raw_fd(), &before)?;
        let mut hidden = hidden(&terminal)?;
        assert_eq!(settings(terminal.as_raw_fd())?.c_iflag & INPUT_OFF, 0);
        // Ctrl+S is a key, which the line drops; é keeps its eighth bit; Enter ends the line.
        type_keys(&controller, "a\x13\u{e9}\r".as_bytes());
        let mut line = crate::SecretLine::with_capacity(16);
        assert_eq!(edit(&mut line, || hidden.next_char())?, LineEnd::Entered);
        hidden.restore()?;
        drop(hidden);
        assert_eq!(line.as_str(), "a\u{e9}");
        assert_eq!(settings(terminal.as_raw_fd())?.c_iflag, before.c_iflag);
        // SAFETY: fcntl takes a descriptor and integers.
        unsafe {
            let flags = libc::fcntl(terminal.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(
                terminal.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            );
        }
        assert!(self::hidden(&terminal).is_err());
        assert_eq!(settings(terminal.as_raw_fd())?.c_iflag, before.c_iflag);
        Ok(())
    }

    /// A descriptor in Linux's access mode 3, for ioctls alone, is a terminal to neither read
    /// nor write.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_descriptor_for_ioctls_alone_is_no_terminal_to_use() {
        let (_controller, terminal) = pseudo_terminal();
        let path =
            std::ffi::CString::new(format!("/proc/self/fd/{}", terminal.as_raw_fd())).unwrap();
        // SAFETY: open reads the NUL-terminated path, which lives for the call.
        let ioctls = unsafe { libc::open(path.as_ptr(), 3 | libc::O_NOCTTY) };
        assert!(ioctls >= 0, "{}", io::Error::last_os_error());
        // SAFETY: the descriptor was just opened, and nothing else owns it.
        let ioctls = unsafe { OwnedFd::from_raw_fd(ioctls) };
        assert!(!terminal_for(ioctls.as_raw_fd(), libc::O_RDONLY));
        assert!(!terminal_for(ioctls.as_raw_fd(), libc::O_WRONLY));
        assert!(terminal_for(terminal.as_raw_fd(), libc::O_RDONLY));
        assert!(terminal_for(terminal.as_raw_fd(), libc::O_WRONLY));
    }

    /// Ctrl+C cancels the line, and the drop restores the terminal all the same.
    #[test]
    fn a_cancelled_line_restores_the_terminal() -> io::Result<()> {
        let (controller, terminal) = pseudo_terminal();
        let before = settings(terminal.as_raw_fd())?;
        let mut hidden = hidden(&terminal)?;
        type_keys(&controller, b"ab\x03");
        let mut line = crate::SecretLine::with_capacity(64);
        let cancelled = edit(&mut line, || hidden.next_char());
        drop(hidden);
        assert_eq!(cancelled?, LineEnd::Cancelled);
        assert_eq!(
            settings(terminal.as_raw_fd())?.c_lflag & !LOCAL_STATE,
            before.c_lflag & !LOCAL_STATE
        );
        Ok(())
    }

    /// The read-back after a restore passes over the bits the terminal changes by itself, such
    /// as the PENDIN macOS sets when line editing comes back on, and still sees echo left off.
    #[test]
    fn a_restore_reads_back_the_settings_but_not_the_terminal_state() -> io::Result<()> {
        let (_controller, terminal) = pseudo_terminal();
        let then = settings(terminal.as_raw_fd())?;
        let mut now = then;
        now.c_lflag |= LOCAL_STATE;
        assert!(same(&now, &then));
        now.c_lflag ^= libc::ECHO;
        assert!(!same(&now, &then));
        Ok(())
    }

    /// The keys waiting when the reading starts, and those left when it ends, are dropped, as
    /// soon as they were written: those still on their way included.
    #[test]
    fn keys_outside_the_reading_are_dropped() -> io::Result<()> {
        let (controller, terminal) = pseudo_terminal();
        type_keys(&controller, b"typed ahead\r");
        let mut hidden = hidden(&terminal)?;
        type_keys(&controller, b"inside\rafter Enter\r");
        let mut line = crate::SecretLine::with_capacity(64);
        assert_eq!(edit(&mut line, || hidden.next_char())?, LineEnd::Entered);
        hidden.restore()?;
        assert_eq!(line.as_str(), "inside");
        assert_eq!(waiting(&terminal), 0);
        Ok(())
    }

    /// Bytes that make no UTF-8 are refused, not taken into the line.
    #[test]
    fn bytes_that_are_no_text_are_refused() -> io::Result<()> {
        // A byte no UTF-8 starts with, characters cut short, and a surrogate's encoding.
        for bytes in [&b"\xff"[..], b"\xc3a", b"\xe2\x82a", b"\xed\xa0\x80"] {
            let (controller, terminal) = pseudo_terminal();
            let mut hidden = hidden(&terminal)?;
            type_keys(&controller, bytes);
            let refused = hidden.next_char().map_err(|error| error.kind());
            assert_eq!(refused, Err(io::ErrorKind::InvalidData), "{bytes:?}");
        }
        Ok(())
    }
}
