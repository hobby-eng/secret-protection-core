//! [`open_channels`]: what a process still has open after isolation that could carry a secret out:
//! descriptors, and memory shared with something outside it.

use std::io;

/// What kind of thing a descriptor is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelKind {
    /// A socket, connected or not.
    Socket,
    /// A regular file.
    File,
    /// A pipe or a FIFO.
    Pipe,
    /// A terminal recognized by `isatty`. A terminal whose ioctls are denied can appear as a device.
    Terminal,
    /// Another device, such as /dev/null.
    Device,
    /// A directory.
    Directory,
    /// Something else, such as an event counter or an `io_uring` ring, which keeps running
    /// requests after isolation.
    Other,
    /// It could not be examined.
    Unknown,
}

/// One descriptor the process has open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel {
    /// Its number.
    pub descriptor: i32,
    /// What it is.
    pub kind: ChannelKind,
    /// Whether it is open for writing; `None` when that could not be read.
    pub writable: Option<bool>,
}

/// Memory the process can write that is shared with whatever else maps the same memory or file:
/// after isolation a write there still reaches another process or a file, with no descriptor open.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedMapping {
    /// Where it starts.
    pub start: usize,
    /// How many bytes it spans.
    pub length: usize,
    /// What the system names it, such as a file's path, `/dev/zero (deleted)` for shared anonymous
    /// memory, `/SYSV…` or `/memfd:…`; empty when it has no name.
    pub name: String,
}

/// The descriptors and shared memory found, and whether the look at them was whole.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenChannels {
    /// The descriptors, sorted by number, standard streams included.
    pub channels: Vec<Channel>,
    /// The shared mappings the process can write, now or after `mprotect`, sorted by address.
    /// This crate's own secret memory is left out.
    pub shared_mappings: Vec<SharedMapping>,
    /// Whether every descriptor and mapping was listed and examined. When false, a channel may be
    /// missing or unknown, and empty lists prove nothing.
    pub complete: bool,
}

impl OpenChannels {
    /// `Ok` when the look was whole and found no descriptor beyond `expected` and no shared
    /// mapping: the check to make after isolation, before a secret is read, as no new channel can
    /// open then. Else what was unexpected, with `complete` as found.
    pub fn only(&self, expected: &[i32]) -> Result<(), Self> {
        let unexpected = Self {
            channels: (self.channels.iter())
                .filter(|channel| !expected.contains(&channel.descriptor))
                .copied()
                .collect(),
            shared_mappings: self.shared_mappings.clone(),
            complete: self.complete,
        };
        let clean = unexpected.complete
            && unexpected.channels.is_empty()
            && unexpected.shared_mappings.is_empty();
        if clean { Ok(()) } else { Err(unexpected) }
    }
}

/// The descriptors visible to the calling thread, and the shared memory of the process. On Linux
/// each thread can have a separate descriptor table, and another thread sharing that table may
/// open or close an entry meanwhile. Isolation keeps descriptors and mappings made before it
/// usable, so this shows what is left; [`OpenChannels::only`] requires that nothing else is.
/// Fails where the system can't list them (`Unsupported` on Windows and in WebAssembly).
pub fn open_channels() -> io::Result<OpenChannels> {
    crate::os::open_channels()
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn open_channels_name_sockets_files_and_pipes() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let path = std::env::temp_dir().join(format!("spc-channels-{}", std::process::id()));
        let file = std::fs::File::create_new(&path).unwrap();
        let reading = std::fs::File::open(&path).unwrap();
        let null = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        let (pipe, _writer) = std::io::pipe().unwrap();
        let open = open_channels().unwrap();
        assert!(open.complete);
        let of = |descriptor: i32| {
            open.channels
                .iter()
                .find(|channel| channel.descriptor == descriptor)
                .map(|channel| (channel.kind, channel.writable))
        };
        assert_eq!(
            of(socket.as_raw_fd()),
            Some((ChannelKind::Socket, Some(true)))
        );
        assert_eq!(of(file.as_raw_fd()), Some((ChannelKind::File, Some(true))));
        assert_eq!(
            of(reading.as_raw_fd()),
            Some((ChannelKind::File, Some(false)))
        );
        // A writable device is no file.
        assert_eq!(
            of(null.as_raw_fd()),
            Some((ChannelKind::Device, Some(true)))
        );
        assert_eq!(of(pipe.as_raw_fd()), Some((ChannelKind::Pipe, Some(false))));
        // The listing's own descriptor is closed by the time it is examined, and drops out.
        let numbers: Vec<i32> = open.channels.iter().map(|c| c.descriptor).collect();
        let mut sorted = numbers.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(numbers, sorted);
        drop((file, reading));
        std::fs::remove_file(&path).unwrap();
    }
}
