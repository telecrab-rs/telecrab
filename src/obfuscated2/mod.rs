pub mod conn;
pub mod frame;
pub mod server;

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes256;
use ctr::Ctr128BE;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::proxy::HasPeerAddr;

use self::conn::ObfuscatedStream;
pub use self::frame::*;
use super::faketls::conn::FakeTlsStream;
use super::safety::constant_time_compare;

#[derive(Clone, Copy, Debug)]
struct ClientHandshakeFrame(HandShakeFrame);

impl HandShakeFrame {
    fn new(data: [u8; HANDSHAKE_FRAME_LEN]) -> HandShakeFrame {
        HandShakeFrame { data }
    }

    fn dc(&self) -> i32 {
        i32::from_be_bytes([0, 0, 0, self.data[HANDSHAKE_FRAME_OFFSET_DC]])
    }

    fn key(&self) -> &[u8; HANDSHAKE_KEY_LEN] {
        self.data[HANDSHAKE_FRAME_OFFSET_KEY..HANDSHAKE_FRAME_OFFSET_IV]
            .try_into()
            .unwrap()
    }

    fn iv(&self) -> &[u8; HANDSHAKE_IV_LEN] {
        self.data[HANDSHAKE_FRAME_OFFSET_IV..HANDSHAKE_FRAME_OFFSET_CONNECTION_TYPE]
            .try_into()
            .unwrap()
    }

    fn with_key(&mut self, key: &[u8; HANDSHAKE_KEY_LEN]) -> &mut Self {
        self.data[HANDSHAKE_FRAME_OFFSET_KEY..HANDSHAKE_FRAME_OFFSET_IV].copy_from_slice(key);
        self
    }

    fn with_iv(&mut self, iv: &[u8; HANDSHAKE_IV_LEN]) -> &mut Self {
        self.data[HANDSHAKE_FRAME_OFFSET_IV..HANDSHAKE_FRAME_OFFSET_CONNECTION_TYPE]
            .copy_from_slice(iv);
        self
    }

    fn connection_type(&self) -> &[u8] {
        &self.data[HANDSHAKE_FRAME_OFFSET_CONNECTION_TYPE..HANDSHAKE_FRAME_OFFSET_DC]
    }

    fn invert(&self) -> HandShakeFrame {
        let mut inverted = self.data;
        inverted[HANDSHAKE_FRAME_OFFSET_KEY..HANDSHAKE_FRAME_OFFSET_CONNECTION_TYPE].reverse();
        HandShakeFrame { data: inverted }
    }
}

impl ClientHandshakeFrame {
    fn decryptor(&self, secret: &[u8]) -> Ctr128BE<Aes256> {
        let mut hasher = Sha256::new();
        hasher.update(self.0.key());
        hasher.update(secret);
        let result = hasher.finalize();

        make_aes_ctr(&result, &self.0.iv())
    }

    fn encryptor(&self, secret: &[u8]) -> Ctr128BE<Aes256> {
        let inverted_handshake = self.0.invert();
        let mut hasher = Sha256::new();
        hasher.update(inverted_handshake.key());
        hasher.update(secret);
        let result = hasher.finalize();

        make_aes_ctr(&result, inverted_handshake.iv())
    }
}

// Helper method to encapsulate AES CTR creation
pub(crate) fn make_aes_ctr(key: &[u8], iv: &[u8; HANDSHAKE_IV_LEN]) -> Ctr128BE<Aes256> {
    Ctr128BE::<Aes256>::new(key.into(), iv.into())
}

// Assuming handshakeFrame and other related structs and methods are properly defined...
// Example client handshake function:
pub async fn client_handshake<'a, 'b>(
    proxy: &crate::proxy::Proxy,
    secret: &[u8],
    socket: &'a mut FakeTlsStream<&'b mut tokio::net::TcpStream>,
) -> Result<ObfuscatedStream<&'a mut FakeTlsStream<&'b mut tokio::net::TcpStream>>, std::io::Error>
{
    let mut data = [0u8; HANDSHAKE_FRAME_LEN];
    socket.read_exact(&mut data).await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Failed to read handshake frame: {:?}", e),
        )
    })?;

    proxy.log_event(crate::proxy::ProxyEvent::DataReceived(
        socket.peer_addr().unwrap(),
        data.to_vec(),
    ))?;

    client_handshake_handle(socket, secret, &mut data)
}

pub fn client_handshake_handle<T>(
    inner_socket: T,
    secret: &[u8],
    data: &mut [u8; HANDSHAKE_FRAME_LEN],
) -> Result<ObfuscatedStream<T>, std::io::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let handshake = ClientHandshakeFrame(HandShakeFrame { data: *data });

    let mut decryptor = handshake.decryptor(secret);
    let encryptor = handshake.encryptor(secret);

    decryptor.apply_keystream(data);

    // Check connection type:
    let hsf = HandShakeFrame::new(*data);
    let requested_connection_type = hsf.connection_type();

    if !constant_time_compare(requested_connection_type, &HANDSHAKE_CONNECTION_TYPE) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "unsupported connection type: {}",
                hex::encode(requested_connection_type)
            ),
        ));
    }

    Ok(ObfuscatedStream::new(
        inner_socket,
        hsf.dc(),
        encryptor,
        decryptor,
    ))
}

pub async fn server_handshake<'a>(
    _proxy: &'a crate::proxy::Proxy,
    mut socket: tokio::net::TcpStream,
    dc: i32,
) -> Result<ObfuscatedStream<tokio::net::TcpStream>, std::io::Error> {
    let mut handshake = generate_server_handshake_frame();
    let original_key = handshake.0.key().clone();
    let original_iv = handshake.0.iv().clone();

    let mut encryptor = handshake.decryptor();
    let decryptor = handshake.encryptor();

    encryptor.apply_keystream(&mut handshake.0.data);
    handshake.0.with_key(&original_key).with_iv(&original_iv);

    socket.write_all(&handshake.0.data).await?;

    Ok(conn::ObfuscatedStream::new(
        socket, dc, encryptor, decryptor,
    ))
}

fn generate_server_handshake_frame() -> server::ServerHandshakeFrame {
    let mut frame = HandShakeFrame {
        data: [0; HANDSHAKE_FRAME_LEN],
    };
    loop {
        frame.data = rand::random();
        if frame.data[0] == 0xef {
            continue;
        }
        // if frame[..4] matches (little endian u32) 0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0xeeeeeeee we regenerate the rand again
        let header = u32::from_le_bytes(frame.data[..4].try_into().unwrap());
        if header == 0x44414548
            || header == 0x54534f50
            || header == 0x20544547
            || header == 0x4954504f
            || header == 0xeeeeeeee
        {
            continue;
        }

        // if frame[4..8] are zeros, we regenerate the rand again
        if frame.data[4..8] == [0, 0, 0, 0] {
            continue;
        }

        break;
    }
    // Now we set the connection type
    frame.data[HANDSHAKE_FRAME_OFFSET_CONNECTION_TYPE..HANDSHAKE_FRAME_OFFSET_DC]
        .copy_from_slice(&HANDSHAKE_CONNECTION_TYPE);

    server::ServerHandshakeFrame(frame)
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use super::*;
    use base64::Engine;

    #[test]
    fn test_known_ok_handshake_1() -> Result<(), std::io::Error> {
        let secret = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("NnoYmu4Y+jHBkAVO/UqOlQ")
            .unwrap();
        let handshake_frame = base64::prelude::BASE64_STANDARD_NO_PAD.decode("gDcXwaMY4RwlR+nJw+ILDr123UJHHjjE/U5pF4m/Y04AmH7lEpEL6UYRnIYDbDlOHSDxc1ToziPvNlJJh8RMow")
        .unwrap();
        let dc = 2;
        let write_content_text = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("AQIDBAUGBwgJCg")
            .unwrap();
        let write_content_cipher = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("wZV3TR39l9nRoQ")
            .unwrap();
        let read_content_text = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("4wZj6mUUew")
            .unwrap();
        let read_content_cipher = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("YWJjZGVmZw")
            .unwrap();

        let mut data = [0u8; HANDSHAKE_FRAME_LEN];
        data.copy_from_slice(&handshake_frame);

        let mock_frame_socket = Cursor::new(handshake_frame.to_vec());
        let mut conn = client_handshake_handle(mock_frame_socket, &secret, &mut data).unwrap();
        assert_eq!(conn.dc, dc);

        // Use the decryptor to decrypt the encrypted text to read
        let mut read_content = read_content_cipher.to_vec();
        conn.decryptor().apply_keystream(&mut read_content);
        assert_eq!(read_content, read_content_text);

        // Use the encryptor to encrypt the decrypted text to write
        let mut write_content = write_content_text.to_vec();
        conn.encryptor().apply_keystream(&mut write_content);
        assert_eq!(write_content, write_content_cipher);

        Ok(())
    }

    #[test]
    fn test_known_ok_handshake_2() -> Result<(), std::io::Error> {
        let secret = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("NnoYmu4Y+jHBkAVO/UqOlQ")
            .unwrap();
        let handshake_frame = base64::prelude::BASE64_STANDARD_NO_PAD.decode("M2WyxeiwIQB+ZOFxNzSNHtu9OdESkfxv3JkKFimCxUoYA3BD/Ql9nXB/OIonCKLUKCcS0VzZ2P6/+5oQ9GI8YA")
        .unwrap();
        let dc = 2;
        let write_content_text = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("AQIDBAUGBwgJCg")
            .unwrap();
        let write_content_cipher = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("tzAwrCz00odERg")
            .unwrap();
        let read_content_text = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("QkIvwGQDgA")
            .unwrap();
        let read_content_cipher = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("YWJjZGVmZw")
            .unwrap();

        let mut data = [0u8; HANDSHAKE_FRAME_LEN];
        data.copy_from_slice(&handshake_frame);

        let mock_frame_socket = Cursor::new(handshake_frame.to_vec());
        let mut conn = client_handshake_handle(mock_frame_socket, &secret, &mut data).unwrap();
        assert_eq!(conn.dc, dc);

        // Use the decryptor to decrypt the encrypted text to read
        let mut read_content = read_content_cipher.to_vec();
        conn.decryptor().apply_keystream(&mut read_content);
        assert_eq!(read_content, read_content_text);

        // Use the encryptor to encrypt the decrypted text to write
        let mut write_content = write_content_text.to_vec();
        conn.encryptor().apply_keystream(&mut write_content);
        assert_eq!(write_content, write_content_cipher);

        Ok(())
    }
}
