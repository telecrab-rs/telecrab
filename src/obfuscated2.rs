use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use aes::Aes256;
use ctr::Ctr128BE;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::io::Read;
use tokio::io::AsyncReadExt;

use crate::safety::constant_time_compare;

const DEFAULT_DC: u8 = 2;
const HANDSHAKE_FRAME_LEN: usize = 64;
const HANDSHAKE_KEY_LEN: usize = 32;
const HANDSHAKE_IV_LEN: usize = 16;
const HANDSHAKE_CONNECTION_TYPE_LEN: usize = 4;

const HANDSHAKE_FRAME_OFFSET_START: usize = 8;
const HANDSHAKE_FRAME_OFFSET_KEY: usize = HANDSHAKE_FRAME_OFFSET_START;
const HANDSHAKE_FRAME_OFFSET_IV: usize = HANDSHAKE_FRAME_OFFSET_KEY + HANDSHAKE_KEY_LEN;
const HANDSHAKE_FRAME_OFFSET_CONNECTION_TYPE: usize = HANDSHAKE_FRAME_OFFSET_IV + HANDSHAKE_IV_LEN;
const HANDSHAKE_FRAME_OFFSET_DC: usize =
    HANDSHAKE_FRAME_OFFSET_CONNECTION_TYPE + HANDSHAKE_CONNECTION_TYPE_LEN;

// We only support faketls
const HANDSHAKE_CONNECTION_TYPE: [u8; 4] = [0xdd, 0xdd, 0xdd, 0xdd];

#[derive(Clone)]
pub struct Connection {
    dc: i32,
    encryptor: Ctr128BE<Aes256>,
    decryptor: Ctr128BE<Aes256>,
}

struct ClientHandshakeFrame(HandShakeFrame);

struct HandShakeFrame {
    data: [u8; HANDSHAKE_FRAME_LEN],
}

impl HandShakeFrame {
    fn new(data: [u8; HANDSHAKE_FRAME_LEN]) -> HandShakeFrame {
        HandShakeFrame { data }
    }

    fn dc(&self) -> i32 {
        i32::from_be_bytes([0, 0, 0, self.data[HANDSHAKE_FRAME_OFFSET_DC]])
    }

    fn key(&self) -> &[u8] {
        &self.data[HANDSHAKE_FRAME_OFFSET_KEY..HANDSHAKE_FRAME_OFFSET_IV]
    }

    fn iv(&self) -> &[u8; HANDSHAKE_IV_LEN] {
        self.data[HANDSHAKE_FRAME_OFFSET_IV..HANDSHAKE_FRAME_OFFSET_CONNECTION_TYPE]
            .try_into()
            .unwrap()
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

        Self::make_aes_ctr(&result, &self.0.iv())
    }

    fn encryptor(&self, secret: &[u8]) -> Ctr128BE<Aes256> {
        let inverted_handshake = self.0.invert();
        let mut hasher = Sha256::new();
        hasher.update(inverted_handshake.key());
        hasher.update(secret);
        let result = hasher.finalize();

        Self::make_aes_ctr(&result, inverted_handshake.iv().try_into().unwrap())
    }

    // Helper method to encapsulate AES CTR creation
    fn make_aes_ctr(key: &[u8], iv: &[u8; HANDSHAKE_IV_LEN]) -> Ctr128BE<Aes256> {
        Ctr128BE::<Aes256>::new(key.into(), iv.into())
    }
}

// Assuming handshakeFrame and other related structs and methods are properly defined...
// Example client handshake function:
pub async fn client_handshake(
    proxy: &crate::proxy::Proxy,
    secret: &[u8],
    socket: &mut tokio::net::TcpStream,
) -> Result<Connection, std::io::Error> {
    let mut data = [0u8; HANDSHAKE_FRAME_LEN];
    socket.read_exact(&mut data).await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Failed to read handshake frame: {:?}", e),
        )
    })?;

    proxy
        .log_event(crate::proxy::ProxyEvent::DataReceived(
            socket.peer_addr().unwrap(),
            data.to_vec(),
        ))
        .await?;

    client_handshake_handle(secret, &mut data)
}

pub fn client_handshake_handle(
    secret: &[u8],
    data: &mut [u8; HANDSHAKE_FRAME_LEN],
) -> Result<Connection, std::io::Error> {
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

    Ok(Connection {
        dc: hsf.dc(),
        encryptor,
        decryptor,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use base64::Engine;

    #[test]
    fn test_known_ok_handshake() {
        let secret = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("NnoYmu4Y+jHBkAVO/UqOlQ")
            .unwrap();
        let handshake_frame = base64::prelude::BASE64_STANDARD_NO_PAD.decode("gDcXwaMY4RwlR+nJw+ILDr123UJHHjjE/U5pF4m/Y04AmH7lEpEL6UYRnIYDbDlOHSDxc1ToziPvNlJJh8RMow")
        .unwrap();
        let dc = 2;
        let encrypted_text = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("AQIDBAUGBwgJCg")
            .unwrap();
        let encrypted_cipher = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("wZV3TR39l9nRoQ")
            .unwrap();
        let decrypted_text = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("4wZj6mUUew")
            .unwrap();
        let decrypted_cipher = base64::prelude::BASE64_STANDARD_NO_PAD
            .decode("YWJjZGVmZw")
            .unwrap();

        let mut data = [0u8; HANDSHAKE_FRAME_LEN];
        data.copy_from_slice(&handshake_frame);
        let conn = client_handshake_handle(&secret, &mut data).unwrap();
        assert_eq!(conn.dc, dc);
    }
}
