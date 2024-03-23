mod record;

use crate::{cli::Cli, config::User, secret::SECRET_KEY_LEN};
use hmac::Mac;
use std::io::{Error, ErrorKind};

const SERVER_HELLO_SUFFIX: [u8; 17] = [
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

const RANDOM_LENGTH: usize = 32;
const CLIENT_HELLO_RANDOM_OFFSET: u8 = 6;
const CLIENT_HELLO_SESSION_ID_OFFSET: usize = CLIENT_HELLO_RANDOM_OFFSET as usize + RANDOM_LENGTH;
const CLIENT_HELLO_MIN_LENGTH: usize = 6;
const WELCOME_PACKET_RANDOM_OFFSET: usize = 11;
const HANDSHAKE_TYPE_CLIENT: u8 = 0x01;
const HANDSHAKE_TYPE_SERVER: u8 = 0x02;
const CHANGE_CYPHER_VALUE: u8 = 0x01;
const EXTENSION_SNI: u16 = 0x0000;

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

pub struct ClientHello<'a> {
    user: Option<&'a User>,
    time: u32,
    random: [u8; RANDOM_LENGTH],
    session_id: Vec<u8>,
    host: String,
    cipher_suites: Vec<u16>,
}

impl<'a> ClientHello<'a> {
    fn new() -> Self {
        Self {
            user: None,
            time: 0,
            random: [0; RANDOM_LENGTH],
            session_id: Vec::new(),
            host: "".to_string(),
            cipher_suites: Vec::new(),
        }
    }

    pub fn check(
        client_hello: &'a mut [u8],
        users: &'a [User],
        cli: &Cli,
    ) -> Result<ClientHello<'a>, Error> {
        for user in users.iter() {
            let mut client_hello_copy = client_hello.to_vec().clone();
            if let Ok(client_hello) = parse_client_hello(&mut client_hello_copy, user.secret.key) {
                cli.log(2, format!("User {} logged in", user.user_info));
                return Ok(client_hello.with_user(user));
            }
        }
        Err(Error::new(ErrorKind::InvalidData, "User not found"))
    }

    fn with_user<'b>(self, user: &'b User) -> ClientHello<'b> {
        ClientHello {
            user: Some(user),
            ..self
        }
    }

    pub fn check_valid(self) -> Result<Self, Error> {
        if self.cipher_suites.is_empty() {
            return Err(Error::new(ErrorKind::InvalidData, "No cipher suites"));
        }

        if self.host.is_empty() {
            return Err(Error::new(ErrorKind::InvalidData, "No host"));
        }

        Ok(self)
    }

    pub fn generate_server_hello(&self) -> Vec<u8> {
        let mut server_hello = Vec::new();
        server_hello.extend_from_slice(&SERVER_HELLO_SUFFIX);
        server_hello
    }
}

pub fn parse_client_hello<'a>(
    handshake: &'a mut [u8],
    secret: [u8; SECRET_KEY_LEN],
) -> Result<ClientHello<'a>, String> {
    let mut hello = ClientHello::new();

    if handshake.len() < CLIENT_HELLO_MIN_LENGTH {
        return Err("Client hello too short".to_string());
    }
    if handshake[0] != HANDSHAKE_TYPE_CLIENT {
        return Err("Invalid handshake type".to_string());
    }

    let handshake_size_bytes = &handshake[0..4];
    let handshake_size = u32::from_be_bytes(handshake_size_bytes.try_into().unwrap()) as usize;

    if handshake.len() - 4 != handshake_size {
        return Err(format!(
            "Invalid handshake size. Manifested={}, real={}",
            handshake_size,
            handshake.len() - 4
        ));
    }

    let mut empty_random = client_hello_empty_random();

    hello
        .random
        .copy_from_slice(&handshake[CLIENT_HELLO_RANDOM_OFFSET as usize..]);

    handshake[CLIENT_HELLO_RANDOM_OFFSET as usize..].copy_from_slice(&empty_random);

    let rec = record::TlsRecord::new(
        record::RecordType::Handshake,
        record::Version::TLS10,
        handshake,
    );

    // mac is calculated for the whole record, not only the payload
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&secret).unwrap();
    mac.update(&rec.to_bytes());

    let mut computed_random = mac.finalize().into_bytes();

    for i in 0..RANDOM_LENGTH {
        computed_random[i] ^= hello.random[i];
    }

    if !constant_time_compare(
        &computed_random,
        &handshake[CLIENT_HELLO_RANDOM_OFFSET as usize..],
    ) {
        return Err("Randoms do not match".to_string());
    }

    let timestamp = handshake[CLIENT_HELLO_SESSION_ID_OFFSET..CLIENT_HELLO_SESSION_ID_OFFSET + 4]
        .try_into()
        .unwrap();
    hello.time = u32::from_be_bytes(timestamp);

    parse_session_id(&mut hello, &handshake);
    parse_cipher_suite_sni(&mut hello, &handshake);

    Ok(hello)
}

fn parse_session_id(hello: &mut ClientHello, handshake: &[u8]) {
    let session_id_length = handshake[CLIENT_HELLO_SESSION_ID_OFFSET];
    hello.session_id = handshake[CLIENT_HELLO_SESSION_ID_OFFSET + 1
        ..CLIENT_HELLO_SESSION_ID_OFFSET + 1 + session_id_length as usize]
        .to_vec();
}

fn parse_cipher_suite_sni(hello: &mut ClientHello, handshake: &[u8]) {
    let cipher_suites_length_offset = CLIENT_HELLO_SESSION_ID_OFFSET + 1 + hello.session_id.len();
    let cipher_suites_length = take_u16(handshake, cipher_suites_length_offset);
    hello.cipher_suites = handshake[cipher_suites_length_offset + 2
        ..cipher_suites_length_offset + 2 + cipher_suites_length as usize]
        .chunks(2)
        .map(|x| u16::from_be_bytes(x.try_into().unwrap()))
        .collect();

    let compression_methods_length_offset =
        cipher_suites_length_offset + 2 + cipher_suites_length as usize;
    let compression_methods_length = handshake[compression_methods_length_offset];

    let extensions_offset =
        compression_methods_length_offset + 1 + compression_methods_length as usize;
    let extensions_length = take_u16(handshake, extensions_offset);

    let mut offset = extensions_offset + 2;

    while offset < extensions_offset + 2 + extensions_length as usize {
        let extension_type = take_u16(handshake, offset);
        offset += 2;
        let extension_length = take_u16(handshake, offset);
        offset += 2;

        if extension_type == EXTENSION_SNI {
            let server_name_list_length = take_u16(handshake, offset);
            offset += 2;
            let server_name_type = handshake[offset];
            offset += 1;
            let server_name_length = take_u16(handshake, offset);
            offset += 2;
            hello.host =
                String::from_utf8_lossy(&handshake[offset..offset + server_name_length as usize])
                    .to_string();
            break;
        }
    }
}

fn take_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }

    result == 0
}
