use std::{io::Cursor, pin::Pin, task::Poll};

use rand::Rng;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter},
    net::TcpStream,
};

use crate::{
    faketls::{self, conn::FakeTlsStream, record::TlsRecord},
    obfuscated2::conn::ObfuscatedStream,
};

pub(crate) trait Socket: AsyncReadExt + AsyncWriteExt + Unpin {}
impl<T> Socket for T where T: AsyncReadExt + AsyncWriteExt + Unpin {}
pub(crate) trait SocketWithAddr<'a, R, W>:
    Socket + HasPeerAddr + Splittable<'a, R, W> + Unpin
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
}

impl<'a, T, R, W> SocketWithAddr<'a, R, W> for T
where
    T: Socket + HasPeerAddr + Splittable<'a, R, W> + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
}

pub(crate) trait HasPeerAddr {
    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr>;
}

impl HasPeerAddr for TcpStream {
    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        TcpStream::peer_addr(&self)
    }
}
impl<T> HasPeerAddr for &mut T
where
    T: HasPeerAddr,
{
    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        HasPeerAddr::peer_addr(*self)
    }
}
impl<T> HasPeerAddr for Box<T>
where
    T: HasPeerAddr,
{
    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        HasPeerAddr::peer_addr(&**self)
    }
}

pub trait Splittable<'a, R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn split(&'a mut self) -> (R, W);
}

impl<'a, T, R, W> Splittable<'a, R, W> for &mut T
where
    T: Splittable<'a, R, W>,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn split(&'a mut self) -> (R, W) {
        Splittable::split(*self)
    }
}

impl<'a> Splittable<'a, Box<tokio::net::tcp::ReadHalf<'a>>, Box<tokio::net::tcp::WriteHalf<'a>>>
    for Box<TcpStream>
{
    fn split(
        &'a mut self,
    ) -> (
        Box<tokio::net::tcp::ReadHalf<'a>>,
        Box<tokio::net::tcp::WriteHalf<'a>>,
    ) {
        let (r, w) = TcpStream::split(self);
        (Box::new(r), Box::new(w))
    }
}
impl<'a> Splittable<'a, tokio::net::tcp::ReadHalf<'a>, tokio::net::tcp::WriteHalf<'a>>
    for &'a mut TcpStream
{
    fn split(
        &'a mut self,
    ) -> (
        tokio::net::tcp::ReadHalf<'a>,
        tokio::net::tcp::WriteHalf<'a>,
    ) {
        TcpStream::split(self)
    }
}

// Split a Cursor<Vec<u8>> into two isolated cursors
impl<'a> Splittable<'a, Cursor<Vec<u8>>, Cursor<Vec<u8>>> for Cursor<Vec<u8>> {
    fn split(&'a mut self) -> (Cursor<Vec<u8>>, Cursor<Vec<u8>>) {
        let len = self.get_ref().len();
        let data = self.get_mut();
        let (r, w) = data.split_at_mut(len);
        (
            std::io::Cursor::new(r.to_vec()),
            std::io::Cursor::new(w.to_vec()),
        )
    }
}

pub struct HalfReadObfuscatedStream<'a, T>
where
    T: AsyncRead + Unpin,
{
    inner: BufReader<T>,
    decryptor: &'a mut ctr::Ctr128BE<aes::Aes256>,
}

pub struct HalfWriteObfuscatedStream<'a, T>
where
    T: AsyncWrite + Unpin,
{
    inner: BufWriter<T>,
    encryptor: &'a mut ctr::Ctr128BE<aes::Aes256>,
}

impl<'a, T, R, W> Splittable<'a, HalfReadObfuscatedStream<'a, R>, HalfWriteObfuscatedStream<'a, W>>
    for ObfuscatedStream<T>
where
    T: AsyncRead + AsyncWrite + Splittable<'a, R, W> + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn split(&'a mut self) -> (HalfReadObfuscatedStream<R>, HalfWriteObfuscatedStream<W>) {
        let (inner, dc, encryptor, decryptor) = (
            &mut self.inner,
            self.dc,
            &mut self.encryptor,
            &mut self.decryptor,
        );
        let (r, w) = inner.get_mut().split();
        (
            HalfReadObfuscatedStream {
                inner: BufReader::new(r),
                decryptor,
            },
            HalfWriteObfuscatedStream {
                inner: BufWriter::new(w),
                encryptor,
            },
        )
    }
}

impl<'a, T> AsyncRead for HalfReadObfuscatedStream<'a, T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use aes::cipher::StreamCipher;

        let self_mut = self.get_mut();
        let filled = buf.filled().len();
        let poll_result = Pin::new(&mut self_mut.inner).poll_read(cx, buf);

        let data = &mut buf.filled_mut()[filled..];
        self_mut.decryptor.apply_keystream(data);

        poll_result
    }
}

impl<'a, T> AsyncWrite for HalfWriteObfuscatedStream<'a, T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        use aes::cipher::StreamCipher;

        let self_mut = self.get_mut();
        let mut encrypted_data = buf.to_vec();
        self_mut.encryptor.apply_keystream(&mut encrypted_data);

        Pin::new(&mut self_mut.inner).poll_write(cx, &encrypted_data)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let self_mut = self.get_mut();
        Pin::new(&mut self_mut.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let self_mut = self.get_mut();
        Pin::new(&mut self_mut.inner).poll_shutdown(cx)
    }
}

pub struct HalfReadFakeTlsStream<T>
where
    T: AsyncRead + Unpin,
{
    inner: BufReader<T>,
    read_buffer: Vec<u8>,
    partial_payload: Vec<u8>,
}

pub struct HalfWriteFakeTlsStream<T>
where
    T: AsyncWrite + Unpin,
{
    inner: BufWriter<T>,
}

impl<'a, T, R, W> Splittable<'a, HalfReadFakeTlsStream<R>, HalfWriteFakeTlsStream<W>>
    for FakeTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Splittable<'a, R, W> + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    fn split(&'a mut self) -> (HalfReadFakeTlsStream<R>, HalfWriteFakeTlsStream<W>) {
        let (r, w) = Splittable::split(self.inner.get_mut());
        (
            HalfReadFakeTlsStream {
                inner: BufReader::new(r),
                read_buffer: Vec::with_capacity(u16::MAX as usize),
                partial_payload: Vec::new(),
            },
            HalfWriteFakeTlsStream {
                inner: BufWriter::new(w),
            },
        )
    }
}

impl<'a, T> AsyncRead for HalfReadFakeTlsStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let self_mut = self.get_mut();

        loop {
            // We may still have a partial payload from the previous read.
            if self_mut.partial_payload.len() > 0 {
                let partial_len = self_mut.partial_payload.len();
                let to_copy = std::cmp::min(partial_len, buf.remaining());
                buf.put_slice(&self_mut.partial_payload[..to_copy]);

                // If we have copied the entire partial payload, clear it.
                if to_copy == partial_len {
                    self_mut.partial_payload.clear();
                } else {
                    // Otherwise, remove the copied bytes from the partial payload.
                    self_mut
                        .partial_payload
                        .splice(..to_copy, std::iter::empty());
                }

                // Returning ok due to the partial payload
                // Let our caller call us again if hungry for more data
                return Poll::Ready(Ok(()));
            }

            // Read a complete TLS record from the buffer if available.
            if let Some(tls_record) = TlsRecord::from_bytes(&self_mut.read_buffer).ok() {
                match tls_record.header().type_ {
                    faketls::record::RecordType::ApplicationData => {
                        // These are the only ones we care about for now
                        // Fall through to read the payload
                    }
                    faketls::record::RecordType::ChangeCipherSpec => {
                        // We ignore ChangeCipherSpec requests
                        // Remove this record from the buffer and
                        // continue to the next record
                        self_mut
                            .read_buffer
                            .splice(..tls_record.bytes.len(), std::iter::empty());
                        continue;
                    }
                    // Other records we fail on them
                    record => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Unsupported record type: {:?}", record),
                        )))
                    }
                }

                // Consumes the bytes related to the TLS record,
                // leave any remaining bytes in the buffer.
                self_mut
                    .read_buffer
                    .splice(..tls_record.bytes.len(), std::iter::empty());

                // Extract payload from the TLS record and copy it into buf.
                let to_copy = std::cmp::min(tls_record.payload().len(), buf.remaining());
                buf.put_slice(&tls_record.payload()[..to_copy]);

                // If the payload is larger than the buffer, we need to store the
                // remaining payload in the stream for the next read.
                if to_copy < tls_record.payload().len() {
                    self_mut.partial_payload = tls_record.payload()[to_copy..].to_vec();
                }
                // If we successfully read a record and put its payload into buf, return Ok.
                return Poll::Ready(Ok(()));
            }

            // If no complete TLS record is available in the buffer,
            // try reading more data from the inner stream.
            if self_mut.read_buffer.capacity() < u16::MAX as usize {
                self_mut
                    .read_buffer
                    .reserve(u16::MAX as usize - self_mut.read_buffer.len());
            }

            let mut temp_buf = vec![0u8; 4096];
            let mut temp_read_buf = tokio::io::ReadBuf::new(&mut temp_buf);

            match Pin::new(&mut self_mut.inner).poll_read(cx, &mut temp_read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = temp_read_buf.filled();
                    if !filled.is_empty() {
                        self_mut.read_buffer.extend_from_slice(filled);
                    } else {
                        // Probably EOF
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Err(e)) => {
                    eprintln!("[faketls] got inner error here: {:?}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }

            // Continue the loop to try parsing the buffer again.
        }
    }
}

impl<'a, T> AsyncWrite for HalfWriteFakeTlsStream<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        // The max record size is
        const MAX_RECORD_SIZE: usize = u16::MAX as usize; // Max u16, which will fit in the header
        let mut written_offset = 0;
        let buf_len = buf.len();
        let mut inner_buf = Vec::<u8>::new();

        while written_offset < buf_len {
            let chunk_size =
                std::cmp::min(rand::thread_rng().gen_range(1..MAX_RECORD_SIZE), buf_len);
            let next_write_offset = written_offset + chunk_size;

            let tls_record = TlsRecord::new(
                faketls::record::RecordType::ApplicationData,
                faketls::record::Version::TLS12,
                buf[written_offset..next_write_offset].to_vec(),
            );
            inner_buf.extend_from_slice(&tls_record.bytes);
            written_offset += chunk_size;
        }

        // Now, the underlying poll_write will write the inner_buf to the stream
        // And will write 5 more bytes than the inner_buf, which is the header of the record
        // So, we need to return the length adjusted (inner_buf.len() - 5, or buf_len)
        match Pin::new(&mut self.get_mut().inner).poll_write(cx, &inner_buf)? {
            Poll::Ready(size) => {
                if size < inner_buf.len() {
                    // We have not written everything! We don't need to hold the remaining things in the buffer
                    // since it's expected to be written in the next write.
                    // We can just return the size written so far.
                    Poll::Ready(Ok(size - 5))
                } else {
                    Poll::Ready(Ok(buf_len))
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let self_mut = self.get_mut();
        Pin::new(&mut self_mut.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let self_mut = self.get_mut();
        Pin::new(&mut self_mut.inner).poll_shutdown(cx)
    }
}
