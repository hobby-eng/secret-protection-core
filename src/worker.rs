//! A worker process for the secret work. It cleans up and isolates itself before reading anything,
//! tells the parent what took effect, and only then gets requests: length-prefixed frames on its
//! standard input and output, read straight into a [`Secret`].

use std::fmt;
use std::io::{self, Read, Write};

use crate::protect::{Isolation, Missing, Options, Protection, Secret};

/// The variable through which a worker learns that it is one: the options its parent chose, and
/// whether it keeps the terminal.
pub(crate) const WORKER: &str = "SECRET_PROTECTION_CORE_WORKER";

/// What a worker sends before anything else: one byte for each protection, then whether its
/// start left it clean.
const REPORT_BYTES: usize = Protection::COUNT + 1;

/// A child process, started from this same program, that does the secret work in full isolation.
/// It shares no memory with the parent and inherits only its two pipes; on Windows it runs in an
/// AppContainer without network. Android and iOS can't start one. `main` must call [`serve`] first.
/// Answers should carry what the parent needs, never the password or the key.
pub struct Worker {
    process: crate::os::WorkerProcess,
    isolation: Isolation,
    broken: bool,
    /// Whether the worker ended, once it was ended.
    ended: Option<bool>,
}

/// Why a worker did not start. It was ended before any request reached it.
#[derive(Debug)]
pub enum WorkerError {
    /// The process did not start, or ended before it said what read back.
    Start(io::Error),
    /// The worker's start was not clean: it holds a descriptor besides its standard streams,
    /// inherited or opened by the program before `serve`, could not list its descriptors, or
    /// could not leave the terminal.
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
    /// Starts this program again as a worker with `options`, without the terminal. Returns it only
    /// once the worker holds nothing of its parent's but its pipes and every protection in
    /// `required` is confirmed in it; else the worker is ended and nothing was sent to it.
    pub fn start(options: Options, required: &[Protection]) -> Result<Self, WorkerError> {
        Self::starting(options, required, false)
    }

    /// As [`Worker::start`], but the worker keeps the terminal (Linux and macOS): its standard
    /// error and the terminal the program runs on, so that the program's code there can read a
    /// password and the parent never holds it. This crate reads none and changes no terminal
    /// setting: the echo is the program's to turn off, through standard error, since a terminal
    /// opened after the isolation takes no settings (Linux 6.10).
    pub fn start_on_terminal(
        options: Options,
        required: &[Protection],
    ) -> Result<Self, WorkerError> {
        Self::starting(options, required, true)
    }

    fn starting(
        options: Options,
        required: &[Protection],
        terminal: bool,
    ) -> Result<Self, WorkerError> {
        // A program whose `main` came here before `serve` would start itself without end.
        if std::env::var_os(WORKER).is_some() {
            return Err(WorkerError::Start(io::Error::other(
                "a worker starts no worker: main calls serve first",
            )));
        }
        let setting = format!("{},{}", options.to_bits(), u8::from(terminal));
        let mut process =
            crate::os::WorkerProcess::start(&setting, terminal).map_err(WorkerError::Start)?;
        let started = Self::report(&mut process).and_then(|(isolation, clean)| {
            if !clean {
                return Err(WorkerError::Unclean);
            }
            isolation.require(required).map_err(WorkerError::Missing)
        });
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
    fn report(process: &mut crate::os::WorkerProcess) -> Result<(Isolation, bool), WorkerError> {
        let unreadable = || io::Error::new(io::ErrorKind::InvalidData, "no report of a worker");
        let mut report = [0; REPORT_BYTES];
        process
            .from
            .as_mut()
            .ok_or_else(unreadable)
            .and_then(|from| from.read_exact(&mut report))
            .map_err(WorkerError::Start)?;
        understood(&report).ok_or_else(|| WorkerError::Start(unreadable()))
    }

    /// What read back in the worker when it isolated itself.
    pub fn isolation(&self) -> Isolation {
        self.isolation
    }

    /// Sends `request` to the worker and returns its answer, read straight into a [`Secret`]. An
    /// answer longer than `most` bytes is refused with `InvalidData`. After that, or after any
    /// failed read or write, the pipes are out of step: the worker is ended before this returns,
    /// as [`Worker::end`] does, and every later call is refused. Neither this nor
    /// [`Worker::start`] has a deadline of its own for a worker that is slow to answer.
    pub fn call(&mut self, request: &[u8], most: usize) -> io::Result<Secret> {
        if self.broken {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the worker was given up after a failed call",
            ));
        }
        let length = u32::try_from(request.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "a request of 4 GiB or more")
        })?;
        let answer = self.exchange(length, request, most);
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

    /// Ends the worker and says whether it ended: its pipes are closed, it gets a second to end
    /// by itself, then is killed and given a second more. False when it is still there, as when
    /// the program may no longer signal other processes; dropping a worker does the same and
    /// cannot say so.
    pub fn end(mut self) -> bool {
        self.finish()
    }

    fn exchange(&mut self, length: u32, request: &[u8], most: usize) -> io::Result<Secret> {
        let closed = || io::Error::from(io::ErrorKind::BrokenPipe);
        let to = self.process.to.as_mut().ok_or_else(closed)?;
        to.write_all(&length.to_le_bytes())?;
        to.write_all(request)?;
        to.flush()?;
        let from = self.process.from.as_mut().ok_or_else(closed)?;
        let mut length = [0; 4];
        from.read_exact(&mut length)?;
        let length = u32::from_le_bytes(length) as usize;
        if length > most {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the answer is longer than allowed",
            ));
        }
        let mut answer = Secret::zeroed(length);
        from.read_exact(answer.as_mut_bytes())?;
        Ok(answer)
    }
}

/// What a worker's report says: its isolation, and whether its start left it clean. `None` for
/// bytes that no worker of this crate sends.
fn understood(report: &[u8; REPORT_BYTES]) -> Option<(Isolation, bool)> {
    let (outcomes, clean) = report.split_at(Protection::COUNT);
    let clean = match clean {
        [0] => false,
        [1] => true,
        _ => return None,
    };
    Some((Isolation::from_bytes(outcomes)?, clean))
}

impl Drop for Worker {
    /// Ends the worker as [`Worker::end`] does, unless it was ended already. A worker that was
    /// left behind is taken off the system's list if it has ended since, without waiting.
    fn drop(&mut self) {
        if !self.finish() {
            self.process.reap();
        }
    }
}

impl fmt::Debug for Worker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Worker")
            .field("isolation", &self.isolation)
            .finish_non_exhaustive()
    }
}

/// What the parent wrote into [`WORKER`]: the options, whether to keep the terminal, and on
/// Windows the name of the pipe. `None` for any other text, an unknown option or flag included.
pub(crate) fn setting(text: &str) -> Option<(u32, bool, &str)> {
    let mut parts = text.splitn(3, ',');
    let options: u32 = parts.next()?.parse().ok()?;
    let terminal = match parts.next()? {
        "0" => false,
        "1" => true,
        _ => return None,
    };
    let rest = parts.next();
    // Only Windows has more: the name of the worker's pipe. On Unix one text, one setting.
    let fits = !cfg!(unix) || rest.is_none();
    let known = Options::from_bits(options).to_bits() == options;
    (known && fits).then_some((options, terminal, rest.unwrap_or_default()))
}

/// The worker side. In a process started by [`Worker::start`] it leaves the terminal, isolates
/// itself, reports, answers requests of up to `most` bytes with `answer` until the parent closes
/// the pipe, and returns `true`; otherwise, and at any later call, `false` at once. Call it
/// first in `main`: it closes nothing, so a worker that holds a descriptor of its own by then
/// says its start was not clean and takes no request (Windows does not look at those).
pub fn serve(most: usize, mut answer: impl FnMut(&[u8]) -> Secret) -> bool {
    static SERVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let text = std::env::var(WORKER).unwrap_or_default();
    let Some((options, terminal, channel)) = setting(&text) else {
        return false;
    };
    if SERVED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    // Whatever a wrong setting makes fail comes before the isolation, which cannot be undone.
    // The streams end when this returns: the parent then sees that the worker serves no more.
    let mut clean = crate::os::starts_clean();
    let Ok(mut streams) = crate::os::worker_streams(channel) else {
        return true;
    };
    if !terminal {
        clean &= crate::os::leave_terminal();
    }
    let isolation = Isolation::enter_with(Options::from_bits(options));
    let mut report = [0; REPORT_BYTES];
    report[..Protection::COUNT].copy_from_slice(&isolation.to_bytes());
    report[Protection::COUNT] = u8::from(clean);
    if streams.write_all(&report).is_err() || !clean {
        return true;
    }
    loop {
        let mut length = [0; 4];
        if streams.read_exact(&mut length).is_err() {
            return true;
        }
        let length = u32::from_le_bytes(length) as usize;
        if length > most {
            return true;
        }
        let mut request = Secret::zeroed(length);
        if streams.read_exact(request.as_mut_bytes()).is_err() {
            return true;
        }
        let reply = answer(request.as_bytes());
        drop(request);
        let Ok(length) = u32::try_from(reply.as_bytes().len()) else {
            return true;
        };
        let sent = streams
            .write_all(&length.to_le_bytes())
            .and_then(|()| streams.write_all(reply.as_bytes()))
            .and_then(|()| streams.flush());
        if sent.is_err() {
            return true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(setting("5,1"), Some((5, true, "")));
        let channel = setting("0,0,//./pipe/name,with,commas");
        let windows = cfg!(windows).then_some((0, false, "//./pipe/name,with,commas"));
        assert_eq!(channel, windows);
        // On Unix nothing follows the two flags, not even a comma.
        #[cfg(unix)]
        assert!(setting("0,0,").is_none() && setting("0,0,3.17").is_none());
        // No other text: a flag that is neither 0 nor 1, or an option this crate does not have.
        for other in ["", "none", "x,1", "7", "0,2", "0,true", "64,0"] {
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
