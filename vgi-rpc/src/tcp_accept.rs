//! Native readiness adapter; accepted streams retain blocking std I/O semantics.

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use mio::{Events, Interest, Poll, Token};

pub(super) struct Listener {
    // Drop the registered socket before its selector (important on Windows).
    listener: mio::net::TcpListener,
    poll: Poll,
    events: Events,
}

impl Listener {
    pub(super) fn new(listener: TcpListener) -> io::Result<Self> {
        let mut listener = mio::net::TcpListener::from_std(listener);
        let poll = Poll::new()?;
        poll.registry()
            .register(&mut listener, Token(0), Interest::READABLE)?;
        Ok(Self {
            listener,
            poll,
            events: Events::with_capacity(1),
        })
    }

    pub(super) fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        self.listener
            .accept()
            .map(|(stream, peer)| (stream.into(), peer))
    }

    pub(super) fn wait(&mut self, timeout: Duration) -> io::Result<()> {
        // Readiness may be spurious. The caller always retries accept and drains
        // until WouldBlock; no accepted socket is registered with this selector.
        self.poll.poll(&mut self.events, Some(timeout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    #[test]
    fn connection_wakes_a_long_wait_and_returns_a_blocking_capable_stream() {
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut listener = Listener::new(socket).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let (start, ready) = mpsc::channel();
        let connector = thread::spawn(move || {
            ready.recv().unwrap();
            thread::sleep(Duration::from_millis(20));
            TcpStream::connect(address).unwrap()
        });
        let before = Instant::now();
        start.send(()).unwrap();
        let (stream, _) = loop {
            listener.wait(Duration::from_secs(5)).unwrap();
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => panic!("{error}"),
            }
        };
        assert!(
            before.elapsed() < Duration::from_secs(2),
            "wait slept through readiness"
        );
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut peer = connector.join().unwrap();
        use std::io::{Read, Write};
        peer.write_all(b"ready").unwrap();
        let mut bytes = [0; 5];
        (&stream).read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ready");
    }

    #[test]
    fn queued_connections_are_drained_and_readiness_rearms() {
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut listener = Listener::new(socket).unwrap();
        for _ in 0..3 {
            let peers: Vec<_> = (0..8)
                .map(|_| TcpStream::connect(address).unwrap())
                .collect();
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut accepted = 0;
            while accepted < peers.len() {
                match listener.accept() {
                    Ok(_) => accepted += 1,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline);
                        listener.wait(Duration::from_millis(20)).unwrap();
                    }
                    Err(error) => panic!("{error}"),
                }
            }
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }
}
