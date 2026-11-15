//! A worker process for the secret work. It isolates itself before reading anything, tells the
//! parent what took effect, and only then gets requests: length-prefixed frames on its standard
//! input and output, read straight into a [`Secret`].

use std::fmt;
use std::io::{self, Read, Write};

use crate::protect::{Isolation, Missing, Options, Protection, Secret};

/// The variable through which a worker learns that it is one, and the options its parent chose.
pub(crate) const WORKER: &str = "SECRET_PROTECTION_CORE_WORKER";

/// A child process, started from this same program, that does the secret work in full isolation.
/// It shares no memory with the parent and inherits only its two pipes; on Windows it runs in an
/// AppContainer without network. Android and iOS can't start one. `main` must call [`serve`] first.
/// Answers should carry what the parent needs, never the password or the key.
pub struct Worker {
    process: crate::os::WorkerProcess,
    isolation: Isolation,
    broken: bool,
}

/// Why a worker did not start.
#[derive(Debug)]
pub enum WorkerError {
    /// The process did not start, or ended before it said what read back.
    Start(io::Error),
    /// Protections the parent required do not hold in the worker, which was ended before any
    /// request reached it.
    Missing(Missing),
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(error) => write!(f, "the worker did not start: {error}"),
            Self::Missing(missing) => write!(f, "the worker is not isolated enough: {missing}"),
        }
    }
}

impl std::error::Error for WorkerError {}

impl Worker {
    /// Starts this program again as a worker with `options`, without the terminal, and returns it
    /// once every protection in `required` reads back in it; else ends it and refuses, before any
    /// request reaches it.
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
        let mut process = crate::os::WorkerProcess::start(options.to_bits(), terminal)
            .map_err(WorkerError::Start)?;
        let mut report = [0; 4];
        if let Err(error) = process.from.read_exact(&mut report) {
            process.finish();
            return Err(WorkerError::Start(error));
        }
        match Isolation::from_bits(u32::from_le_bytes(report)).require(required) {
            Ok(isolation) => Ok(Self {
                process,
                isolation,
                broken: false,
            }),
            Err(missing) => {
                process.finish();
                Err(WorkerError::Missing(missing))
            }
        }
    }

    /// What read back in the worker when it isolated itself.
    pub fn isolation(&self) -> Isolation {
        self.isolation
    }

    /// Sends `request` to the worker and returns its answer, read straight into a [`Secret`]. An
    /// answer longer than `most` bytes is refused with `InvalidData`, and so is every later call:
    /// the rest of that answer still waits in the pipe.
    pub fn call(&mut self, request: &[u8], most: usize) -> io::Result<Secret> {
        if self.broken {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the worker's pipe is out of step",
            ));
        }
        let length = u32::try_from(request.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "a request of 4 GiB or more")
        })?;
        let to = self.process.to.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        to.write_all(&length.to_le_bytes())?;
        to.write_all(request)?;
        to.flush()?;
        let mut length = [0; 4];
        self.process.from.read_exact(&mut length)?;
        let length = u32::from_le_bytes(length) as usize;
        if length > most {
            self.broken = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the answer is longer than allowed",
            ));
        }
        let mut answer = Secret::zeroed(length);
        self.process.from.read_exact(answer.as_mut_bytes())?;
        Ok(answer)
    }
}

impl Drop for Worker {
    /// Closes the worker's input, which ends its [`serve`], and waits for it.
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

/// The worker side. If this process was started by [`Worker::start`], it isolates itself, answers
/// requests with `answer` until the parent closes the pipe, and returns `true`; otherwise it returns
/// `false` at once. Call it first in `main`, before any thread starts.
pub fn serve(mut answer: impl FnMut(&[u8]) -> Secret) -> bool {
    let Some(options) = std::env::var(WORKER)
        .ok()
        .and_then(|bits| bits.parse().ok())
    else {
        return false;
    };
    crate::os::close_inherited();
    let isolation = Isolation::enter_with(Options::from_bits(options));
    let (mut input, mut output) = crate::os::worker_streams();
    if output
        .write_all(&isolation.to_bits().to_le_bytes())
        .is_err()
    {
        return true;
    }
    loop {
        let mut length = [0; 4];
        if input.read_exact(&mut length).is_err() {
            return true;
        }
        let mut request = Secret::zeroed(u32::from_le_bytes(length) as usize);
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
