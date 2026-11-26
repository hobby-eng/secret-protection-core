//! A worker reports its startup checks and isolation before the parent sends a request.
//! Frames travel over standard streams on Unix and a named pipe on Windows.

use std::fmt;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use zeroize::Zeroize;

use crate::protect::{Isolation, Missing, Options, Protection, Secret};

/// The variable through which a worker learns that it is one: the options its parent chose, and
/// whether it works on the terminal.
pub(crate) const WORKER: &str = "SECRET_PROTECTION_CORE_WORKER";

pub(crate) const PIPE_PREFIX: &str = r"\\.\pipe\secret-protection-core.";

/// The first size of the worker's request buffer, at most the limit: one page, which the smallest
/// secret takes anyway.
const REQUEST_BUFFER: usize = 4096;

/// The startup report sent after the platform checks and before application requests.
/// It contains one byte per protection followed by the clean-start flag.
pub(crate) const REPORT_BYTES: usize = Protection::COUNT + 1;

/// The longest frame either side reads, whatever `most` allows: past it a 32-bit system could not
/// reserve the pages, and a `Secret` of that size would end the program. The 256 KiB under
/// `isize::MAX` leave room for the guard pages and the rounding up to pages of up to 64 KiB.
const FRAME_LIMIT: usize = isize::MAX.unsigned_abs() - (256 << 10);

/// A separate process running the same executable on Linux, macOS or Windows.
/// Call [`serve`] first in the worker. The parent checks the startup report and the protections
/// it required before sending a request. A worker must confirm [`Protection::WholeProcess`].
/// Linux closes inherited nonstandard descriptors during spawn. Windows disables inheritance and
/// uses a named pipe in an AppContainer without network capabilities.
pub struct Worker {
    process: crate::os::WorkerProcess,
    isolation: Isolation,
    broken: bool,
    /// Whether the worker ended, once it was ended.
    ended: Option<bool>,
}

/// Why the parent could not admit a worker. It sent no request and attempts to clean up any
/// process it started.
#[derive(Debug)]
pub enum WorkerError {
    /// Launch, transport or startup protocol failed before admission.
    Start(io::Error),
    /// The worker's start was not clean: it holds a descriptor besides its standard streams,
    /// inherited or opened by the program before `serve`, could not list its descriptors, or
    /// could not leave its parent's session.
    Unclean,
    /// Protections the parent required are not confirmed in the worker.
    Missing(Missing),
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(error) => write!(f, "the worker did not start: {error}"),
            Self::Unclean => f.write_str("the worker's start was not clean"),
            Self::Missing(missing) => write!(f, "the worker is not isolated enough: {missing}"),
        }
    }
}

impl std::error::Error for WorkerError {}

impl Worker {
    /// Starts the current executable without a terminal, and returns the worker once its start was
    /// clean and whole-process isolation and `required` are confirmed; no deadline. On Linux it
    /// fails first with `PermissionDenied` unless Yama's `ptrace_scope` is 1 or more and the
    /// program is in the first user namespace: else any process of the user could take the
    /// worker (docs/API.md, "When a worker cannot be started safely").
    pub fn start(options: Options, required: &[Protection]) -> Result<Self, WorkerError> {
        Self::starting(options, required, false, None)
    }

    /// As [`Worker::start`], but the start fails with [`WorkerError::Start`] of kind `TimedOut`
    /// when the worker has not been launched, connected and sent its startup report within
    /// `deadline`. On Unix nothing is launched once the deadline has passed, and a launch that
    /// finishes after it is ended by the launcher. On Windows the profile, the pipe and the
    /// process creation are calls that cannot be cut short: the deadline is read before and after
    /// them.
    /// When the deadline passes, the worker is given up: its channels close, and where a stable
    /// handle exists (Windows, and Linux with a pidfd) it is terminated; elsewhere it ends when it
    /// next touches its channels. The call returns after that shutdown, which waits up to a second, and
    /// after a termination up to a second more (see [`Worker::end`]). A deadline too far ahead for
    /// the clock to hold, such as `Duration::MAX`, waits without one.
    pub fn start_within(
        options: Options,
        required: &[Protection],
        deadline: Duration,
    ) -> Result<Self, WorkerError> {
        Self::starting(options, required, false, due(deadline))
    }

    /// Starts a Linux or macOS worker whose standard error is this program's terminal, opened for
    /// reading and writing, so that the application can read input there without routing it
    /// through the parent; `/dev/null` when no standard stream is a terminal. The worker has no
    /// controlling terminal, so it cannot type into the shell (TIOCSTI) and `/dev/tty` does not
    /// open. There `read_hidden_line` reads with the echo off; as the worker has no job control,
    /// the program must stay the foreground job and leave the terminal alone while it reads. On
    /// Linux it refuses as [`Worker::start`] does.
    pub fn start_on_terminal(
        options: Options,
        required: &[Protection],
    ) -> Result<Self, WorkerError> {
        Self::starting(options, required, true, None)
    }

    fn starting(
        options: Options,
        required: &[Protection],
        terminal: bool,
        deadline: Option<Instant>,
    ) -> Result<Self, WorkerError> {
        // A program whose `main` came here before `serve` would start itself without end.
        if std::env::var_os(WORKER).is_some() {
            return Err(WorkerError::Start(io::Error::other(
                "a worker starts no worker: main calls serve first",
            )));
        }
        // On Linux the worker is dumpable from `exec` until its isolation, and in a user namespace
        // its user owns it stays open to the user's processes after it too. Where any of them may
        // attach, it could take the worker and its channel, and nothing the worker reported could
        // be trusted: no worker starts.
        #[cfg(target_os = "linux")]
        if !crate::os::attaching_restricted() || !crate::os::in_first_user_namespace() {
            return Err(WorkerError::Start(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "any process of this user could attach to a worker: it needs Yama's \
                 kernel.yama.ptrace_scope at 1 or more, and the first user namespace",
            )));
        }
        let setting = format!("{},{}", options.to_bits(), u8::from(terminal));
        let mut process = crate::os::WorkerProcess::start(&setting, terminal, deadline)
            .map_err(WorkerError::Start)?;
        let started = Self::report(&mut process, deadline)
            .and_then(|(isolation, clean)| admit(isolation, clean, required));
        match started {
            Ok(isolation) => Ok(Self {
                process,
                isolation,
                broken: false,
                ended: None,
            }),
            Err(error) => {
                process.finish();
                Err(error)
            }
        }
    }

    /// Reads what the worker says of itself: its isolation, and whether its start left it clean.
    fn report(
        process: &mut crate::os::WorkerProcess,
        deadline: Option<Instant>,
    ) -> Result<(Isolation, bool), WorkerError> {
        let unreadable = || io::Error::new(io::ErrorKind::InvalidData, "no report of a worker");
        let mut report = [0; REPORT_BYTES];
        process
            .exchanging(deadline, |process, deadline| {
                #[cfg(windows)]
                process.observe_threads(deadline)?;
                process.read_exact_until(&mut report, deadline)
            })
            .map_err(WorkerError::Start)?;
        understood(&report).ok_or_else(|| WorkerError::Start(unreadable()))
    }

    /// What read back in the worker when it isolated itself.
    pub fn isolation(&self) -> Isolation {
        self.isolation
    }

    /// Sends a framed request and reads its reply into a [`Secret`]. A request too large for
    /// the four-byte length is rejected before sending. A reply larger than `most` is refused;
    /// up to `most`, the worker decides how much the parent reserves before the bytes arrive, and
    /// like any `Secret` a reservation the system refuses ends the process: choose `most` as the
    /// memory a worker may make the parent take.
    /// A failed exchange closes the transport, attempts shutdown and prevents further calls.
    /// Waiting for the reply has no deadline.
    pub fn call(&mut self, request: &[u8], most: usize) -> io::Result<Secret> {
        self.calling(request, most, None)
    }

    /// As [`Worker::call`], but the call fails with `TimedOut` when the exchange has not finished
    /// within `deadline`, an answer that arrives past it included, and later calls fail with
    /// `BrokenPipe`.
    /// When the deadline passes, the worker is given up: its channels close, and where a stable
    /// handle exists (Windows, and Linux with a pidfd) it is terminated; elsewhere it ends when it
    /// next touches its channels. The call returns after that shutdown, which waits up to a second, and
    /// after a termination up to a second more (see [`Worker::end`]). A deadline too far ahead for
    /// the clock to hold, such as `Duration::MAX`, waits without one.
    pub fn call_within(
        &mut self,
        request: &[u8],
        most: usize,
        deadline: Duration,
    ) -> io::Result<Secret> {
        self.calling(request, most, due(deadline))
    }

    fn calling(
        &mut self,
        request: &[u8],
        most: usize,
        deadline: Option<Instant>,
    ) -> io::Result<Secret> {
        if self.broken {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the worker was given up after a failed call",
            ));
        }
        let length = u32::try_from(request.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "a request of 4 GiB or more")
        })?;
        let answer = self.exchange(length, request, most, deadline);
        if answer.is_err() {
            self.broken = true;
            self.finish();
        }
        answer
    }

    /// Ends the worker, once, and returns whether it ended: a later call waits no second time
    /// and gives the first answer again.
    fn finish(&mut self) -> bool {
        if self.ended.is_none() {
            self.ended = Some(self.process.finish());
        }
        self.ended == Some(true)
    }

    /// Closes the transport and waits up to a second for exit. Windows and Linux with a
    /// spawn-time pidfd can request termination, then wait up to a second more. On macOS
    /// and Linux without a pidfd, a worker still running at the deadline yields false.
    /// A dedicated Unix waiter collects the worker when it exits. On the POSIX fallback
    /// let this library own the child's wait status.
    pub fn end(mut self) -> bool {
        self.finish()
    }

    fn exchange(
        &mut self,
        length: u32,
        request: &[u8],
        most: usize,
        deadline: Option<Instant>,
    ) -> io::Result<Secret> {
        self.process.exchanging(deadline, |process, deadline| {
            process.write_all_until(&length.to_le_bytes(), deadline)?;
            process.write_all_until(request, deadline)?;
            read_answer(|buffer| process.read_exact_until(buffer, deadline), most)
        })
    }
}

/// Reads an answer: four bytes of length, little-endian, then that many bytes. A length above
/// `most` is refused before anything of it is read.
pub(crate) fn read_answer(
    mut read_exact: impl FnMut(&mut [u8]) -> io::Result<()>,
    most: usize,
) -> io::Result<Secret> {
    let mut length = [0; 4];
    read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > most || length > FRAME_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the answer is longer than allowed",
        ));
    }
    let mut answer = Secret::zeroed(length);
    read_exact(answer.as_mut_bytes())?;
    Ok(answer)
}

/// Reads the list of thread IDs a Windows worker's census asks its parent for: a count, then as
/// many IDs, all four bytes little-endian. Zero stands for no observation; any other list must be
/// at most `most` long, of distinct, nonzero, ascending IDs. Portable, so that it is fuzzed.
#[cfg_attr(
    not(any(windows, fuzzing, test)),
    expect(dead_code, reason = "only Windows workers take a census")
)]
pub(crate) fn read_roster(reader: &mut impl Read, most: usize) -> io::Result<Option<Vec<u32>>> {
    let mut word = [0; 4];
    reader.read_exact(&mut word)?;
    let count = u32::from_le_bytes(word) as usize;
    if count == 0 {
        return Ok(None);
    }
    if count > most {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; 4 * count];
    reader.read_exact(&mut bytes)?;
    let mut ids = Vec::with_capacity(count);
    let mut previous = 0;
    for &word in bytes.as_chunks::<4>().0 {
        let id = u32::from_le_bytes(word);
        if id <= previous {
            return Err(io::ErrorKind::InvalidData.into());
        }
        ids.push(id);
        previous = id;
    }
    Ok(Some(ids))
}

/// The instant `deadline` from now. A target that starts no worker answers `Unsupported` without
/// one, before the clock is read: `wasm32-unknown-unknown` has none, and `Instant::now` panics.
fn due(deadline: Duration) -> Option<Instant> {
    if cfg!(any(unix, windows)) {
        Instant::now().checked_add(deadline)
    } else {
        None
    }
}

fn admit(
    isolation: Isolation,
    clean: bool,
    required: &[Protection],
) -> Result<Isolation, WorkerError> {
    if !clean {
        return Err(WorkerError::Unclean);
    }
    isolation
        .require_process_wide(required)
        .map_err(WorkerError::Missing)
}

/// What a worker's report says: its isolation, and whether its start left it clean. `None` for
/// bytes that no worker of this crate sends.
pub(crate) fn understood(report: &[u8; REPORT_BYTES]) -> Option<(Isolation, bool)> {
    let (outcomes, clean) = report.split_at(Protection::COUNT);
    let clean = match clean {
        [0] => false,
        [1] => true,
        _ => return None,
    };
    Some((Isolation::from_bytes(outcomes)?, clean))
}

impl Drop for Worker {
    /// Uses the first shutdown result; the Unix waiter outlives a failed shutdown.
    fn drop(&mut self) {
        self.finish();
    }
}

impl fmt::Debug for Worker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Worker")
            .field("isolation", &self.isolation)
            .finish_non_exhaustive()
    }
}

/// Parses known option bits and a terminal flag. Unix accepts no trailing field. On Windows
/// the terminal flag must be zero, followed by the generated pipe name and launch nonce.
pub(crate) fn setting(text: &str) -> Option<(u32, bool, &str)> {
    let mut parts = text.splitn(3, ',');
    let digits = parts.next()?;
    if digits.len() > 1 && digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let options: u32 = digits.parse().ok()?;
    let terminal = match parts.next()? {
        "0" => false,
        "1" => true,
        _ => return None,
    };
    let rest = parts.next();
    // Only Windows has more: the name of the worker's pipe. On Unix one text, one setting.
    let fits = if cfg!(windows) {
        windows_channel(terminal, rest)
    } else {
        rest.is_none()
    };
    let known = Options::from_bits(options).to_bits() == options;
    (known && fits).then_some((options, terminal, rest.unwrap_or_default()))
}

/// Whether `rest` of a Windows setting names a worker's pipe and its nonce, as the parent writes
/// them: never for a worker on the terminal, which Windows does not start. Portable, so that it
/// is fuzzed on any system.
pub(crate) fn windows_channel(terminal: bool, rest: Option<&str>) -> bool {
    let hex128 = |text: &str| {
        text.len() == 32
            && text
                .bytes()
                .all(|d| d.is_ascii_digit() || (b'a'..=b'f').contains(&d))
    };
    !terminal
        && rest
            .and_then(|channel| channel.split_once(','))
            .is_some_and(|(name, nonce)| {
                name.strip_prefix(PIPE_PREFIX).is_some_and(hex128) && hex128(nonce)
            })
}

/// Handles worker requests of at most `most` bytes with `answer`. Call this at the beginning
/// of `main`, before starting other threads. A recognized worker applies isolation and sends
/// its report before taking requests. Unix checks descriptors still open above standard error.
/// Windows does not enumerate handles the worker has opened. Returns true after handling a
/// worker setting, including a failed worker startup, and false outside worker mode or on a
/// later invocation after the worker role was claimed.
pub fn serve(most: usize, answer: impl FnMut(&[u8]) -> Secret) -> bool {
    static SERVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let text = std::env::var(WORKER).unwrap_or_default();
    let Some((options, _terminal, channel)) = setting(&text) else {
        return false;
    };
    if SERVED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    // Whatever a wrong setting makes fail comes before the isolation, which cannot be undone.
    // The streams end when this returns: the parent then sees that the worker serves no more.
    // On Linux one thread first, as the kernel counts them: another could open a descriptor
    // after the census below, or hold a table of its own that the census misses.
    #[cfg(target_os = "linux")]
    let mut clean = crate::os::one_thread();
    #[cfg(not(target_os = "linux"))]
    let mut clean = true;
    clean &= crate::os::starts_clean();
    let Ok(mut streams) = crate::os::worker_streams(channel) else {
        return true;
    };
    // No worker keeps a controlling terminal: through one, input it typed would reach the shell
    // as the user's own (TIOCSTI). A worker on the terminal has it as standard error.
    clean &= crate::os::leave_terminal();
    // A worker isolates itself alone, at its start: no TSYNC.
    let options = Options {
        all_threads: false,
        ..Options::from_bits(options)
    };
    #[cfg(windows)]
    let Ok(isolation) = streams.enter(options) else {
        return true;
    };
    #[cfg(not(windows))]
    let isolation = Isolation::enter_with(options);
    let mut report = [0; REPORT_BYTES];
    report[..Protection::COUNT].copy_from_slice(&isolation.to_bytes());
    report[Protection::COUNT] = u8::from(clean);
    if streams.write_all(&report).is_err() || !clean || !isolation.whole_process {
        return true;
    }
    requests(&mut streams, most, answer);
    true
}

/// Takes the requests on `streams`, each four bytes of length, little-endian, then that many bytes,
/// and writes back, in the same frame, what `answer` makes of each. Ends when the parent ends the
/// channel, a request is longer than `most` or a write fails.
pub(crate) fn requests(
    streams: &mut (impl Read + Write),
    most: usize,
    mut answer: impl FnMut(&[u8]) -> Secret,
) {
    // One request buffer for the whole service, wiped after each request and grown only for a
    // larger one: a new secret per request would repeat the setup of secret memory and the TLB
    // flush of giving it back, for every keystroke.
    let mut request = Secret::zeroed(REQUEST_BUFFER.min(most));
    loop {
        let mut length = [0; 4];
        if streams.read_exact(&mut length).is_err() {
            return;
        }
        let length = u32::from_le_bytes(length) as usize;
        if length > most || length > FRAME_LIMIT {
            return;
        }
        if length > request.capacity() {
            // The old buffer goes first: both at once would hold twice the locked memory.
            drop(request);
            request = Secret::zeroed(length.max(REQUEST_BUFFER));
        }
        if streams
            .read_exact(&mut request.as_mut_bytes()[..length])
            .is_err()
        {
            return;
        }
        let reply = answer(&request.as_bytes()[..length]);
        request.as_mut_bytes()[..length].zeroize();
        let Ok(length) = u32::try_from(reply.as_bytes().len()) else {
            return;
        };
        let sent = streams
            .write_all(&length.to_le_bytes())
            .and_then(|()| streams.write_all(reply.as_bytes()))
            .and_then(|()| streams.flush());
        if sent.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On a 32-bit system an answer longer than a `Secret` can hold is refused before anything is
    /// allocated, whatever the caller's limit.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn an_answer_past_what_a_secret_holds_is_refused() {
        let mut header = &u32::MAX.to_le_bytes()[..];
        let refused = read_answer(
            |buffer| io::Read::read_exact(&mut header, buffer),
            usize::MAX,
        );
        assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    /// A roster is a count and as many distinct, nonzero, ascending IDs, or zero for none.
    #[test]
    fn only_complete_ordered_rosters_are_accepted() {
        fn parse(words: &[u32]) -> io::Result<Option<Vec<u32>>> {
            let bytes: Vec<_> = words.iter().flat_map(|n| n.to_le_bytes()).collect();
            read_roster(&mut bytes.as_slice(), 1 << 16)
        }
        assert_eq!(parse(&[0]).unwrap(), None);
        assert_eq!(parse(&[2, 1, u32::MAX]).unwrap(), Some(vec![1, u32::MAX]));
        for bad in [&[2, 1][..], &[1, 0], &[2, 1, 1], &[2, 9, 8], &[65_537]] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn whole_process_is_mandatory_even_without_caller_requirements() {
        let mut found = crate::protect::Findings::new();
        found.check(Protection::NoCoreDumps, true, false);
        let report = found.finish();
        for required in [&[][..], &[Protection::NoCoreDumps]] {
            assert!(
                matches!(admit(report, true, required), Err(WorkerError::Missing(m)) if m.missing.contains(&Protection::WholeProcess))
            );
        }
    }

    #[test]
    fn a_required_thread_only_measure_cannot_admit_a_worker() {
        let mut found = crate::protect::Findings::new();
        found.check(Protection::WholeProcess, true, true);
        found.check(Protection::NoNewSockets, true, false);
        assert!(
            matches!(admit(found.finish(), true, &[Protection::NoNewSockets]), Err(WorkerError::Missing(m)) if m.missing == [Protection::NoNewSockets])
        );
    }

    /// A refused start says which refusal it was.
    #[test]
    fn a_refused_start_says_why() {
        let missing = Missing {
            missing: vec![Protection::NoCoreDumps],
            isolation: Isolation::default(),
        };
        let texts = [
            WorkerError::Start(io::ErrorKind::BrokenPipe.into()).to_string(),
            WorkerError::Unclean.to_string(),
            WorkerError::Missing(missing).to_string(),
        ];
        assert!(texts[2].ends_with("no core dumps"), "{texts:?}");
        let unique: std::collections::BTreeSet<&String> = texts.iter().collect();
        assert_eq!(unique.len(), texts.len(), "{texts:?}");
    }

    /// The worker's setting: options, the terminal, and the name of a pipe where there is one.
    #[test]
    fn a_setting_is_read_as_the_parent_writes_it() {
        #[cfg(not(windows))]
        assert_eq!(setting("5,1"), Some((5, true, "")));
        #[cfg(windows)]
        {
            let pipe = format!("{PIPE_PREFIX}0123456789abcdef0123456789abcdef");
            let name = format!("{pipe},fedcba9876543210fedcba9876543210");
            assert_eq!(
                setting(&format!("5,0,{name}")),
                Some((5, false, name.as_str()))
            );
            for bad in [
                format!("0,1,{name}"),
                format!("0,0,{pipe}"),
                format!("0,0,{pipe},"),
                format!("0,0,{name},extra"),
                format!("0,0,{name}0"),
                format!("0,0,{}", name.to_uppercase()),
                "5,1".into(),
            ] {
                assert!(setting(&bad).is_none());
            }
        }
        // On Unix nothing follows the two flags, not even a comma.
        #[cfg(unix)]
        assert!(setting("0,0,").is_none() && setting("0,0,3.17").is_none());
        // No other text: a flag that is neither 0 nor 1, or an option this crate does not have.
        for other in [
            "", "none", "x,1", "+1,0", "01,0", "00,0", "7", "0,2", "0,true", "128,0",
        ] {
            assert_eq!(setting(other), None, "{other}");
        }
    }

    /// A report is taken only as a worker of this crate writes it.
    #[test]
    fn a_report_of_other_bytes_is_refused() {
        let mut report = [0; REPORT_BYTES];
        report[..Protection::COUNT].copy_from_slice(&Isolation::default().to_bytes());
        assert!(matches!(understood(&report), Some((_, false))));
        report[Protection::COUNT] = 1;
        assert!(matches!(understood(&report), Some((_, true))));
        report[Protection::COUNT] = 2;
        assert!(understood(&report).is_none());
        report[Protection::COUNT] = 1;
        report[0] = 16;
        assert!(understood(&report).is_none());
    }
}
