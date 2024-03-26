use std::{pin::Pin, task::Poll};

use crate::{faketls::conn::FakeTlsStream, proxy::HasPeerAddr};
use aes::cipher::StreamCipher;
use aes::Aes256;
use ctr::Ctr128BE;
use tokio::io::{AsyncRead, AsyncWrite, BufStream};

pub struct ObfuscatedStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub dc: i32,
    inner: BufStream<T>,
    encryptor: Ctr128BE<Aes256>,
    decryptor: Ctr128BE<Aes256>,
}

impl<T> ObfuscatedStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(
        inner: T,
        dc: i32,
        encryptor: Ctr128BE<Aes256>,
        decryptor: Ctr128BE<Aes256>,
    ) -> Self {
        Self {
            inner: BufStream::new(inner),
            dc,
            encryptor,
            decryptor,
        }
    }

    #[cfg(test)]
    pub fn encryptor(&mut self) -> &mut Ctr128BE<Aes256> {
        &mut self.encryptor
    }

    #[cfg(test)]
    pub fn decryptor(&mut self) -> &mut Ctr128BE<Aes256> {
        &mut self.decryptor
    }
}

impl<T: HasPeerAddr> HasPeerAddr for ObfuscatedStream<T>
where
    T: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.get_ref().peer_addr()
    }
}
impl<T: HasPeerAddr> HasPeerAddr for &ObfuscatedStream<T>
where
    T: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.get_ref().peer_addr()
    }
}

impl<T> AsyncRead for ObfuscatedStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let self_mut = self.get_mut();

        // We need to read the data from the inner stream and decrypt it
        // before returning it to the caller.

        // First, we read the data from the inner stream.
        // We will use the `buf` parameter to store the data.
        // The `buf` parameter is a `ReadBuf` struct that contains a mutable reference to a buffer.
        // The buffer is a slice of bytes that we can write to.
        // We will use the `filled()` method to get the number of bytes that have been written to the buffer.

        // Next, we need to decrypt the data using the `decryptor` field of the `ObfuscatedStream` struct.
        // The `decryptor` field is an instance of the `Ctr128BE<Aes256>` struct, which is a counter mode AES-256 encryption/decryption algorithm.
        // We will use the `apply_keystream()` method of the `Ctr128BE<Aes256>` struct to decrypt the data.
        // The `apply_keystream()` method takes a mutable reference to the buffer and the length of the data to decrypt.
        // It decrypts the data in place, modifying the buffer in the process.

        // Finally, we return a `Poll::Ready(Ok(()))` result to indicate that the read operation was successful.
        // We also print a message to indicate that the read operation is complete.

        let filled = buf.filled().len();
        let poll_result = Pin::new(&mut self_mut.inner).poll_read(cx, buf);

        let data = &mut buf.filled_mut()[filled..];
        self_mut.decryptor.apply_keystream(data);

        poll_result
    }
}

impl<T> AsyncWrite for ObfuscatedStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        // We need to encrypt the data before writing it to the inner stream.
        // We will use the `encryptor` field of the `ObfuscatedStream` struct to encrypt the data.
        // Use the same strategy as in `poll_read` to encrypt the data before writing it to the inner stream.

        let self_mut = self.get_mut();
        let mut encrypted_data = buf.to_vec();
        self_mut.encryptor.apply_keystream(&mut encrypted_data);

        Pin::new(&mut self_mut.inner).poll_write(cx, &encrypted_data)
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
