use std::{pin::Pin, task::Poll};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, BufStream};

use crate::tokio_utils::HasPeerAddr;

use super::record::TlsRecord;

#[derive(Debug)]
pub struct FakeTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) inner: BufStream<T>,
    read_buffer: Vec<u8>,
    partial_payload: Vec<u8>,
}

impl<T> FakeTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(inner: T) -> Self {
        Self {
            inner: BufStream::new(inner),
            read_buffer: Vec::with_capacity(u16::MAX as usize), // Actual max size of a TLS record
            partial_payload: Vec::new(),
        }
    }
}

impl<T: HasPeerAddr> HasPeerAddr for FakeTlsStream<T>
where
    T: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.get_ref().peer_addr()
    }
}

impl<T: HasPeerAddr> HasPeerAddr for &FakeTlsStream<T>
where
    T: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.get_ref().peer_addr()
    }
}

impl<T> AsyncRead for FakeTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
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
                    super::record::RecordType::ApplicationData => {
                        // These are the only ones we care about for now
                        // Fall through to read the payload
                    }
                    super::record::RecordType::ChangeCipherSpec => {
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

impl<T> AsyncWrite for FakeTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        // We have to write the content as one or more TlsRecords
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
                super::record::RecordType::ApplicationData,
                super::record::Version::TLS12,
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
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_faketls_stream() {
        use super::FakeTlsStream;

        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async {
            // Check that the stream can be created and written to and that the content written to it can be read back and is the same.

            let content_to_check = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

            let mut underlying_tls_stream = Cursor::new(Vec::<u8>::with_capacity(65535));

            let mut stream1 = FakeTlsStream::new(&mut underlying_tls_stream);

            stream1.write_all(&content_to_check).await.unwrap();
            stream1.flush().await.unwrap();

            underlying_tls_stream.set_position(0);

            let mut stream2 = FakeTlsStream::new(&mut underlying_tls_stream);

            let mut read_buf = vec![0u8; 10];
            stream2.read_exact(&mut read_buf).await.unwrap();

            assert_eq!(read_buf, content_to_check);
        });
    }
}
