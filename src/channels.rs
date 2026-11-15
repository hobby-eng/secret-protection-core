//! [`open_channels`]: what a process still has open after isolation that could carry a secret out.

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
    /// A terminal. One opened after the isolation shows as another device from Linux 6.10 on,
    /// where it answers no request.
    Terminal,
    /// Another device, such as /dev/null.
    Device,
    /// A directory.
    Directory,
    /// Something else, such as an event counter.
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

/// The descriptors found open, and whether the look at them was whole.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenChannels {
    /// The descriptors, sorted by number, standard streams included.
    pub channels: Vec<Channel>,
    /// Whether every descriptor was listed and examined. When false, a channel may be missing or
    /// unknown, and an empty list proves nothing.
    pub complete: bool,
}

/// The descriptors the process has open at this moment; another thread may open or close one
/// meanwhile. Isolation keeps descriptors opened before it usable, so this shows what is left: a
/// socket, or anything open for writing, is a way out the program chose. Fails where the system
/// can't list them (`Unsupported` on Windows and in WebAssembly).
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
        let file = std::fs::File::create(&path).unwrap();
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
