mod client_hello;
mod handshake;
mod key_schedule;
mod record;

pub use handshake::chrome_tls_connect;

use key_schedule::ApplicationKeys;
use record::{decrypt_record, make_encrypted_record};

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct ChromeTlsStream {
    tcp: tokio::net::TcpStream,
    read_key: [u8; 16],
    read_iv: [u8; 12],
    write_key: [u8; 16],
    write_iv: [u8; 12],
    read_seq: u64,
    write_seq: u64,
    read_buf: Vec<u8>,
    tcp_buf: Vec<u8>,
    write_pending: Vec<u8>,
}

impl ChromeTlsStream {
    pub(crate) fn new(tcp: tokio::net::TcpStream, keys: ApplicationKeys) -> Self {
        Self {
            tcp,
            read_key: keys.server_key,
            read_iv: keys.server_iv,
            write_key: keys.client_key,
            write_iv: keys.client_iv,
            read_seq: 0,
            write_seq: 0,
            read_buf: Vec::new(),
            tcp_buf: Vec::new(),
            write_pending: Vec::new(),
        }
    }

    fn try_decrypt_records(&mut self) -> io::Result<()> {
        loop {
            if self.tcp_buf.len() < 5 { break; }
            let record_len = u16::from_be_bytes([self.tcp_buf[3], self.tcp_buf[4]]) as usize;
            let total = 5 + record_len;
            if self.tcp_buf.len() < total { break; }

            let ct = self.tcp_buf[0];
            let data = self.tcp_buf[5..total].to_vec();
            self.tcp_buf.drain(..total);

            if ct == 0x14 { continue; }

            if ct == 0x17 {
                match decrypt_record(&data, &self.read_key, &self.read_iv, self.read_seq) {
                    Some((plaintext, inner_type)) => {
                        self.read_seq += 1;
                        if inner_type == 0x15 {
                            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "tls alert"));
                        }
                        if inner_type == 0x17 {
                            self.read_buf.extend_from_slice(&plaintext);
                        }
                    }
                    None => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "tls decrypt failed"));
                    }
                }
            }
        }
        Ok(())
    }
}

impl AsyncRead for ChromeTlsStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.read_buf.is_empty() {
            let n = this.read_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        let mut tmp = [0u8; 16384];
        let mut rb = ReadBuf::new(&mut tmp);
        match Pin::new(&mut this.tcp).poll_read(cx, &mut rb) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                if n == 0 { return Poll::Ready(Ok(())); }
                this.tcp_buf.extend_from_slice(&tmp[..n]);
            }
        }

        if let Err(e) = this.try_decrypt_records() {
            return Poll::Ready(Err(e));
        }

        if !this.read_buf.is_empty() {
            let n = this.read_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for ChromeTlsStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.write_pending.is_empty() {
            let pending = std::mem::take(&mut this.write_pending);
            match Pin::new(&mut this.tcp).poll_write(cx, &pending) {
                Poll::Pending => {
                    this.write_pending = pending;
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "tcp write zero")));
                }
                Poll::Ready(Ok(n)) => {
                    if n < pending.len() {
                        this.write_pending = pending[n..].to_vec();
                    }
                }
            }
        }

        let record = make_encrypted_record(buf, 0x17, &this.write_key, &this.write_iv, this.write_seq);
        this.write_seq += 1;

        match Pin::new(&mut this.tcp).poll_write(cx, &record) {
            Poll::Ready(Ok(n)) if n == record.len() => {}
            Poll::Ready(Ok(n)) => { this.write_pending = record[n..].to_vec(); }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => { this.write_pending = record; }
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.write_pending.is_empty() {
            let pending = std::mem::take(&mut this.write_pending);
            match Pin::new(&mut this.tcp).poll_write(cx, &pending) {
                Poll::Pending => {
                    this.write_pending = pending;
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "tcp write zero")));
                }
                Poll::Ready(Ok(n)) => {
                    if n < pending.len() {
                        this.write_pending = pending[n..].to_vec();
                    }
                }
            }
        }
        Pin::new(&mut this.tcp).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp).poll_shutdown(cx)
    }
}
