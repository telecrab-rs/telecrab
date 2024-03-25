use std::{pin::Pin, task::Poll};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, BufStream};

use crate::faketls::record::TlsRecordFields;

use super::record::TlsRecord;

#[derive(Debug)]
pub struct FakeTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    inner: BufStream<T>,
    buffer: Vec<u8>,
    partial_payload: Vec<u8>,
}

impl<T> FakeTlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(inner: T) -> Self {
        Self {
            inner: BufStream::new(inner),
            buffer: Vec::with_capacity(4096),
            partial_payload: Vec::new(),
        }
    }
}

impl FakeTlsStream<&mut tokio::net::TcpStream> {
    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
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
                    self_mut.partial_payload = self_mut.partial_payload[to_copy..].to_vec();
                }

                println!("Returning ok due to partial payload");
                return Poll::Ready(Ok(()));
            }

            // Read a complete TLS record from the buffer if available.
            if let Some(tls_record) = TlsRecord::from_bytes(&self_mut.buffer).ok() {
                println!(
                    "Got a record here: {:?}",
                    TlsRecordFields::from(&tls_record)
                );
                // Consumes the bytes related to the TLS record,
                // leave any remaining bytes in the buffer.
                self_mut.buffer = self_mut.buffer[tls_record.bytes.len()..].to_vec();

                // Extract payload from the TLS record and copy it into buf.
                let to_copy = std::cmp::min(tls_record.payload().len(), buf.remaining());
                buf.put_slice(&tls_record.payload()[..to_copy]);

                // If the payload is larger than the buffer, we need to store the
                // remaining payload in the stream for the next read.
                if to_copy < tls_record.payload().len() {
                    self_mut.partial_payload = tls_record.payload()[to_copy..].to_vec();
                }

                println!("Return ok due to successful read");
                // If we successfully read a record and put its payload into buf, return Ok.
                return Poll::Ready(Ok(()));
            }

            // If no complete TLS record is available in the buffer,
            // try reading more data from the inner stream.
            const MINIMUM_BUFFER_SIZE: usize = 4096;
            if self_mut.buffer.capacity() < MINIMUM_BUFFER_SIZE {
                self_mut.buffer.reserve(MINIMUM_BUFFER_SIZE);
            }

            let mut temp_buf = vec![0u8; MINIMUM_BUFFER_SIZE];
            let mut temp_read_buf = tokio::io::ReadBuf::new(&mut temp_buf);

            println!(
                "Polling inner stream for more data. We have a temp buffer {:?}",
                temp_read_buf
            );

            match Pin::new(&mut self_mut.inner).poll_read(cx, &mut temp_read_buf) {
                Poll::Ready(Ok(())) => {
                    println!("Got inner OK here, read: {:?}", temp_read_buf.filled());
                    let filled = temp_read_buf.filled();
                    if !filled.is_empty() {
                        self_mut.buffer.extend_from_slice(filled);
                    } else {
                        println!(
                            "Returning Ok due to empty read, but we have remaining: {:?} bytes",
                            self_mut.buffer
                        );
                        // Probably EOF
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Err(e)) => {
                    println!("Got inner error here: {:?}", e);
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
        const MAX_RECORD_SIZE: usize = 65535; // Max u16, which will fit in the header
        let mut written_offset = 0;
        let buf_len = buf.len();
        let mut inner_buf = Vec::<u8>::new();

        while written_offset < buf_len {
            let chunk_size = rand::thread_rng().gen_range(1..MAX_RECORD_SIZE);

            let tls_record = TlsRecord::new(
                super::record::RecordType::ApplicationData,
                super::record::Version::TLS12,
                buf[written_offset..(written_offset + chunk_size).min(buf_len)].to_vec(),
            );
            inner_buf.extend_from_slice(&tls_record.bytes);
            written_offset += chunk_size;
        }
        Pin::new(&mut self.get_mut().inner).poll_write(cx, &inner_buf)
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
