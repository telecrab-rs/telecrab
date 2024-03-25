pub(crate) const SERVER_HELLO_SUFFIX: [u8; 17] = [
    0x00, // no compression
    0x00, 0x2e, // 46 bytes of data
    0x00, 0x2b, // Extension - Supported Versions
    0x00, 0x02, // 2 bytes are following
    0x03, 0x04, // TLS 1.3
    0x00, 0x33, // Extension - Key Share
    0x00, 0x24, // 36 bytes
    0x00, 0x1d, // x25519 curve
    0x00, 0x20, // 32 bytes of key
];

pub(crate) const RANDOM_LENGTH: usize = 32;
pub(crate) const CLIENT_HELLO_RANDOM_OFFSET: usize = 6;
pub(crate) const CLIENT_HELLO_SESSION_ID_OFFSET: usize = CLIENT_HELLO_RANDOM_OFFSET + RANDOM_LENGTH;

pub(crate) const CLIENT_HELLO_MIN_LENGTH: usize = 6;
pub(crate) const WELCOME_PACKET_RANDOM_OFFSET: usize = 11;
pub(crate) const HANDSHAKE_TYPE_CLIENT: u8 = 0x01;
pub(crate) const HANDSHAKE_TYPE_SERVER: u8 = 0x02;
pub(crate) const CHANGE_CYPHER_VALUE: u8 = 0x01;
pub(crate) const EXTENSION_SNI: u16 = 0x0000;

pub fn client_hello_empty_random() -> [u8; RANDOM_LENGTH] {
    [
        0x00, 0x00, 0x00, 0x00, // gmt_unix_time
        0x00, 0x00, 0x00, 0x00, // random_bytes
        0x00, 0x00, 0x00, 0x00, // random_bytes
        0x00, 0x00, 0x00, 0x00, // random_bytes
        0x00, 0x00, 0x00, 0x00, // random_bytes
        0x00, 0x00, 0x00, 0x00, // random_bytes
        0x00, 0x00, 0x00, 0x00, // random_bytes
        0x00, 0x00, 0x00, 0x00, // random_bytes
    ]
}
