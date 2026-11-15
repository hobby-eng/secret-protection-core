//! [`open_channels`]: what a process still has open after isolation that could carry a secret out.

/// What kind of channel a descriptor is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelKind {
    /// A socket, connected or not.
    Socket,
    /// A file open for writing.
    WritableFile,
    /// A pipe or a FIFO.
    Pipe,
    /// A terminal.
    Terminal,
    /// Anything else: a file open only for reading, a directory, an event counter.
    Other,
}

/// One descriptor the process has open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel {
    /// Its number.
    pub descriptor: i32,
    /// What it is.
    pub kind: ChannelKind,
}

/// Every descriptor the process has open, standard streams included, sorted by number. Isolation
/// keeps descriptors opened before it usable, so this shows what is left: a socket or a file open
/// for writing is a way out the program chose. `None` where the system can't list them (Windows,
/// WebAssembly). A worker started by [`crate::Worker`] has only its pipes.
pub fn open_channels() -> Option<Vec<Channel>> {
    crate::os::open_channels()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn open_channels_name_sockets_writable_files_and_pipes() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let path = std::env::temp_dir().join(format!("spc-channels-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        let reading = std::fs::File::open(&path).unwrap();
        let (pipe, _writer) = std::io::pipe().unwrap();
        let channels = open_channels().unwrap();
        let kind = |descriptor: i32| {
            channels
                .iter()
                .find(|channel| channel.descriptor == descriptor)
                .map(|channel| channel.kind)
        };
        assert_eq!(kind(socket.as_raw_fd()), Some(ChannelKind::Socket));
        assert_eq!(kind(file.as_raw_fd()), Some(ChannelKind::WritableFile));
        assert_eq!(kind(reading.as_raw_fd()), Some(ChannelKind::Other));
        assert_eq!(kind(pipe.as_raw_fd()), Some(ChannelKind::Pipe));
        drop((file, reading));
        std::fs::remove_file(&path).unwrap();
    }
}
