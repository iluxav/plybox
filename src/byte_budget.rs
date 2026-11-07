//! A run-wide byte budget, shared by every upstream connection. Reserve
//! before I/O and refund unused bytes, so parallel transfers cannot overshoot.
//! Reads reserve only once data is queued, so an idle connection holds none.
use std::io::{self, Read, Write};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use crate::record::Record;
use serde_json::json;

pub struct Budget {
    limit: Option<u64>,
    remaining: AtomicU64,
    used: AtomicU64,
    reported: AtomicBool,
    direction: &'static str,
    record: Arc<Record>,
}

impl Budget {
    pub fn new(limit: Option<u64>, direction: &'static str, record: Arc<Record>) -> Arc<Self> {
        Arc::new(Self {
            limit,
            remaining: AtomicU64::new(limit.unwrap_or(u64::MAX)),
            used: AtomicU64::new(0),
            reported: AtomicBool::new(false),
            direction,
            record,
        })
    }

    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    pub fn available(&self) -> bool {
        self.limit.is_none() || self.remaining.load(Ordering::Relaxed) > 0
    }

    fn reserve(&self, wanted: usize) -> io::Result<Reservation<'_>> {
        if wanted == 0 {
            return Ok(Reservation {
                budget: self,
                bytes: 0,
            });
        }
        let bytes = if self.limit.is_some() {
            let mut left = self.remaining.load(Ordering::Relaxed);
            loop {
                if left == 0 {
                    if !self.reported.swap(true, Ordering::Relaxed) {
                        self.record.event("net_limit", json!({ "direction": self.direction,
                            "limit": self.limit, "reason": "byte budget exhausted or reserved by concurrent I/O" }));
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("{} byte budget exhausted", self.direction),
                    ));
                }
                let n = left.min(wanted as u64);
                match self.remaining.compare_exchange_weak(
                    left,
                    left - n,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break n as usize,
                    Err(now) => left = now,
                }
            }
        } else {
            wanted
        };
        Ok(Reservation {
            budget: self,
            bytes,
        })
    }
}

struct Reservation<'a> {
    budget: &'a Budget,
    bytes: usize,
}
impl Reservation<'_> {
    fn commit(&mut self, used: usize) {
        self.budget.used.fetch_add(used as u64, Ordering::Relaxed);
        self.bytes -= used;
    }
}
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.budget.limit.is_some() {
            self.budget
                .remaining
                .fetch_add(self.bytes as u64, Ordering::Relaxed);
        }
    }
}

/// Wrap the upstream TCP transport, below TLS. Counts TCP payload bytes
/// including TLS handshakes/records, excluding TCP/IP headers and retries.
pub struct Metered<S> {
    pub stream: S,
    upload: Arc<Budget>,
    download: Arc<Budget>,
}
impl<S> Metered<S> {
    pub fn with_stream<T>(&self, stream: T) -> Metered<T> {
        Metered::new(stream, self.upload.clone(), self.download.clone())
    }
    pub fn new(stream: S, upload: Arc<Budget>, download: Arc<Budget>) -> Self {
        Self {
            stream,
            upload,
            download,
        }
    }
}
/// How many bytes a read would return right now, waiting (as a read would,
/// honouring its timeout) until there is at least one or the stream ends.
/// Consumes nothing: data stays queued for the read that follows.
pub trait Peek {
    fn ready(&self, buf: &mut [u8]) -> io::Result<usize>;
}
impl Peek for std::net::TcpStream {
    fn ready(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.peek(buf)
    }
}
impl<T: AsRef<[u8]>> Peek for std::io::Cursor<T> {
    fn ready(&self, buf: &mut [u8]) -> io::Result<usize> {
        let left = (self.get_ref().as_ref().len() as u64).saturating_sub(self.position());
        Ok(left.min(buf.len() as u64) as usize)
    }
}

impl<S: Read + Peek> Read for Metered<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Wait for data first and reserve only what is queued: a connection
        // blocked on a quiet upstream holds none of the shared budget, and
        // the end of a stream is seen even when the budget is spent.
        let queued = self.stream.ready(buf)?;
        if queued == 0 {
            return Ok(0);
        }
        let mut r = self.download.reserve(queued)?;
        let n = self.stream.read(&mut buf[..r.bytes])?;
        r.commit(n);
        Ok(n)
    }
}
impl<S: Write> Write for Metered<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut r = self.upload.reserve(buf.len())?;
        let n = self.stream.write(&buf[..r.bytes])?;
        r.commit(n);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn budget(n: u64) -> Arc<Budget> {
        Budget::new(
            Some(n),
            "test",
            Arc::new(Record::open(std::path::Path::new("/dev/null")).unwrap()),
        )
    }

    #[test]
    fn connections_share_upload_and_download_caps() {
        let up = budget(5);
        let down = budget(3);
        let mut a = Metered::new(Cursor::new(vec![1; 20]), up.clone(), down.clone());
        let mut b = Metered::new(Cursor::new(vec![1; 20]), up.clone(), down.clone());
        assert_eq!(a.write(b"abcd").unwrap(), 4);
        assert_eq!(b.write(b"efgh").unwrap(), 1);
        assert_eq!(
            a.write(b"z").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(a.read(&mut [0; 2]).unwrap(), 2);
        assert_eq!(b.read(&mut [0; 2]).unwrap(), 1);
        assert!(b.read(&mut [0; 1]).is_err());
        assert_eq!((up.used(), down.used()), (5, 3));
        assert_eq!(b.write(&[]).unwrap(), 0);
        assert_eq!(b.read(&mut []).unwrap(), 0);
    }

    #[test]
    fn short_writes_and_errors_refund_reservations() {
        struct Short(bool);
        impl Write for Short {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                if self.0 {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(b.len().min(1))
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let up = budget(3);
        let mut s = Metered::new(Short(true), up.clone(), budget(0));
        assert!(s.write(b"abc").is_err());
        s.stream.0 = false;
        s.write_all(b"abc").unwrap();
        assert_eq!(up.used(), 3);
        assert!(s.write(b"x").is_err());
    }

    #[test]
    fn an_idle_connection_holds_no_download_budget() {
        use std::net::{TcpListener, TcpStream};
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let down = budget(10);
        // Connection A: the upstream never sends; a reader blocks on it.
        let idle = TcpStream::connect(addr).unwrap();
        let (_idle_peer, _) = l.accept().unwrap();
        let mut a = Metered::new(idle.try_clone().unwrap(), budget(0), down.clone());
        let blocked = std::thread::spawn(move || a.read(&mut [0; 16384]).map_err(|e| e.kind()));
        std::thread::sleep(std::time::Duration::from_millis(50));
        // Connection B has data and must get the whole budget meanwhile.
        let busy = TcpStream::connect(addr).unwrap();
        let (mut busy_peer, _) = l.accept().unwrap();
        busy_peer.write_all(&[7; 10]).unwrap();
        let mut b = Metered::new(busy, budget(0), down.clone());
        let mut got = [0; 16384];
        assert_eq!(b.read(&mut got).unwrap(), 10, "the idle reader held budget");
        // A wakes at EOF without needing budget, then everything is accounted.
        idle.shutdown(std::net::Shutdown::Read).unwrap();
        drop(_idle_peer);
        assert_eq!(blocked.join().unwrap(), Ok(0));
        assert_eq!(down.used(), 10);
    }

    #[test]
    fn concurrent_writers_never_exceed_the_shared_cap() {
        let up = budget(10001);
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let up = up.clone();
                std::thread::spawn(move || {
                    let mut s = Metered::new(Vec::new(), up, budget(0));
                    while s.write(&[0; 97]).is_ok() {}
                    s.stream.len()
                })
            })
            .collect();
        let written: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(written, 10001);
        assert_eq!(up.used(), 10001);
    }
}
