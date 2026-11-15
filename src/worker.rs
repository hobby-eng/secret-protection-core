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
}

/// Why a worker did not start. It was ended before any request reached it.
#[derive(Debug)]
pub enum WorkerError {
    /// The process did not start, or ended before it said what read back.
    Start(io::Error),
    /// The worker could not confirm that it closed every descriptor it inherited, or could not
    /// leave the terminal.
    Unclean,
    /// Protections the parent required are not confirmed in the worker.
    Missing(Missing),
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(error) => write!(f, "the worker did not start: {error}"),
            Self::Unclean => f.write_str("the worker could not shed what it inherited"),
            Self::Missing(missing) => write!(f, "the worker is not isolated enough: {missing}"),
        }
    }
}

impl std::error::Error for WorkerError {}

impl Worker {
    /// Starts this program again as a worker with `options`, without the terminal. Returns it only
    /// once the worker closed what it inherited and every protection in `required` is confirmed
    /// in it; else the worker is ended and nothing was sent to it.
    pub fn start(options: Options, required: &[Protection]) -> Result<Self, WorkerError> {
        Self::starting(options, required, false)
    }

    /// As [`Worker::start`], but the worker keeps the terminal (Linux and macOS): its standard
    /// error and the terminal the program runs on, so that it can read a password from the
    /// terminal itself, opened only for reading, and the parent never holds it.
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
    /// failed read or write, the pipes are out of step: they are closed, the worker ends, and
    /// every later call is refused.
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
            self.process.close();
        }
        answer
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
    /// Closes both pipes, which ends the worker's [`serve`], and waits for it; a worker that does
    /// not end within a second is killed.
    fn drop(&mut self) {
        self.process.finish();
    }
}

impl fmt::Debug for Worker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Worker")
            .field("isolation", &self.isolation)
            .finish_non_exhaustive()
    }
}

/// The options and whether to keep the terminal, as the parent wrote them into [`WORKER`].
fn setting() -> Option<(u32, bool)> {
    let setting = std::env::var(WORKER).ok()?;
    let (options, terminal) = setting.split_once(',')?;
    Some((options.parse().ok()?, terminal == "1"))
}

/// The worker side. If this process was started by [`Worker::start`], it sheds what it inherited,
/// isolates itself, reports, then answers requests of up to `most` bytes with `answer` until the
/// parent closes the pipe, and returns `true`; otherwise it returns `false` at once. Call it first
/// in `main`, before any thread starts. A worker whose start was not clean takes no request.
pub fn serve(most: usize, mut answer: impl FnMut(&[u8]) -> Secret) -> bool {
    let Some((options, terminal)) = setting() else {
        return false;
    };
    let mut clean = crate::os::close_inherited();
    if !terminal {
        clean &= crate::os::leave_terminal();
    }
    let isolation = Isolation::enter_with(Options::from_bits(options));
    let (mut input, mut output) = crate::os::worker_streams();
    let mut report = [0; REPORT_BYTES];
    report[..Protection::COUNT].copy_from_slice(&isolation.to_bytes());
    report[Protection::COUNT] = u8::from(clean);
    if output.write_all(&report).is_err() || !clean {
        return true;
    }
    loop {
        let mut length = [0; 4];
        if input.read_exact(&mut length).is_err() {
            return true;
        }
        let length = u32::from_le_bytes(length) as usize;
        if length > most {
            return true;
        }
        let mut request = Secret::zeroed(length);
        if input.read_exact(request.as_mut_bytes()).is_err() {
            return true;
        }
        let reply = answer(request.as_bytes());
        drop(request);
        let Ok(length) = u32::try_from(reply.as_bytes().len()) else {
            return true;
        };
        let sent = output
            .write_all(&length.to_le_bytes())
            .and_then(|()| output.write_all(reply.as_bytes()))
            .and_then(|()| output.flush());
        if sent.is_err() {
            return true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
