pub mod record;

use crate::{cli::Cli, config::User, secret::SECRET_KEY_LEN};
use hmac::Mac;
use std::io::{Error, ErrorKind};

use self::record::TlsRecord;
use rand::Rng;
use x25519_dalek::{self, X25519_BASEPOINT_BYTES};

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

#[derive(Debug)]
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
        client_hello: &'a [u8],
        users: &'a [User],
        cli: &Cli,
    ) -> Result<ClientHello<'a>, Error> {
        let record = record::TlsRecord::from_bytes(&client_hello)?;

        for user in users.iter() {
            let mut client_hello_copy = record.payload.to_vec().clone();
            let client_hello = parse_client_hello(cli, &mut client_hello_copy, user.secret.key)
                .map_err(|str| Error::new(ErrorKind::Other, str))?;

            if client_hello.is_none() {
                continue;
            }
            cli.log(2, format!("User {} logged in", user.user_info));
            return Ok(client_hello.unwrap().with_user(user));
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

    pub fn generate_welcome_packet(&self, buffer: &mut Vec<u8>) {
        let mut welcome_packet = Vec::new();
        self.generate_server_hello(&mut welcome_packet);

        let mut record = TlsRecord::new(
            record::RecordType::Handshake,
            record::Version::TLS12,
            &welcome_packet,
        );
        buffer.extend_from_slice(&record.to_bytes());

        record = TlsRecord::new(
            record::RecordType::ChangeCipherSpec,
            record::Version::TLS12,
            &[CHANGE_CYPHER_VALUE],
        );
        buffer.extend_from_slice(&record.to_bytes());

        let rand_length = rand::random::<u8>() as usize;
        let mut random_garbage = vec![0; rand_length];
        rand::thread_rng().fill(random_garbage.as_mut_slice());

        record = TlsRecord::new(
            record::RecordType::ApplicationData,
            record::Version::TLS12,
            &random_garbage,
        );
        buffer.extend_from_slice(&record.to_bytes());

        // Now we have to calculate the MAC
        let mut mac =
            hmac::Hmac::<sha2::Sha256>::new_from_slice(&self.user.unwrap().secret.key).unwrap();
        mac.update(&self.random);
        mac.update(&buffer);
        buffer[WELCOME_PACKET_RANDOM_OFFSET..WELCOME_PACKET_RANDOM_OFFSET + 32]
            .copy_from_slice(&mac.finalize().into_bytes());
    }

    pub fn generate_server_hello(&self, server_hello: &mut Vec<u8>) {
        let mut body_buf = Vec::new();
        let mut slice_buf = [0u8; 2];
        let digest: [u8; RANDOM_LENGTH] = rand::random();

        slice_buf.copy_from_slice((record::Version::TLS12 as u16).to_be_bytes().as_ref());
        body_buf.extend_from_slice(&slice_buf);
        body_buf.extend_from_slice(&digest);
        body_buf.push(self.session_id.len() as u8);
        body_buf.extend_from_slice(&self.session_id);

        slice_buf.copy_from_slice((self.cipher_suites[0]).to_be_bytes().as_ref());
        body_buf.extend_from_slice(&slice_buf);
        body_buf.extend_from_slice(&SERVER_HELLO_SUFFIX);

        let scalar: [u8; 32] = rand::random();

        let curve = x25519_dalek::x25519(scalar, X25519_BASEPOINT_BYTES);
        body_buf.extend_from_slice(&curve);

        let header = [
            HANDSHAKE_TYPE_SERVER,
            0x00,
            0x00,
            (body_buf.len() as u8).to_be(),
        ];
        server_hello.extend_from_slice(&header);
    }
}

pub fn parse_client_hello<'a>(
    cli: &Cli,
    handshake: &'a mut [u8],
    secret: [u8; SECRET_KEY_LEN],
) -> Result<Option<ClientHello<'a>>, String> {
    let mut hello = ClientHello::new();

    if handshake.len() < CLIENT_HELLO_MIN_LENGTH {
        return Err("Client hello too short".to_string());
    }
    if handshake[0] != HANDSHAKE_TYPE_CLIENT {
        return Err(format!("Invalid handshake type: {}", handshake[0]).to_string());
    }

    // Bytes are [0, handshake[1], handshake[2], handshake[3]]
    let handshake_size = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;

    if handshake.len() - 4 != handshake_size {
        return Err(format!(
            "Invalid handshake size. Manifested={}, real={}",
            hex::encode(handshake_size.to_be_bytes()),
            hex::encode((handshake.len() - 4).to_be_bytes())
        ));
    }

    let empty_random = client_hello_empty_random();

    hello.random.copy_from_slice(
        &handshake[CLIENT_HELLO_RANDOM_OFFSET as usize
            ..CLIENT_HELLO_RANDOM_OFFSET as usize + RANDOM_LENGTH],
    );

    handshake
        [CLIENT_HELLO_RANDOM_OFFSET as usize..CLIENT_HELLO_RANDOM_OFFSET as usize + RANDOM_LENGTH]
        .copy_from_slice(&empty_random);

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
        &computed_random[..computed_random.len() - 4],
        &handshake[CLIENT_HELLO_RANDOM_OFFSET as usize
            ..CLIENT_HELLO_RANDOM_OFFSET as usize + RANDOM_LENGTH - 4],
    ) {
        // Probably just means that the user did not log in with this secret
        return Ok(None);
    }

    let timestamp = handshake[CLIENT_HELLO_SESSION_ID_OFFSET..CLIENT_HELLO_SESSION_ID_OFFSET + 4]
        .try_into()
        .unwrap();
    hello.time = u32::from_be_bytes(timestamp);

    parse_session_id(&mut hello, &handshake);
    parse_cipher_suite_sni(cli, &mut hello, &handshake);

    Ok(Some(hello))
}

fn parse_session_id(hello: &mut ClientHello, handshake: &[u8]) {
    let session_id_length = handshake[CLIENT_HELLO_SESSION_ID_OFFSET];
    hello.session_id = handshake[CLIENT_HELLO_SESSION_ID_OFFSET + 1
        ..CLIENT_HELLO_SESSION_ID_OFFSET + 1 + session_id_length as usize]
        .to_vec();
}

fn parse_cipher_suite_sni(cli: &Cli, hello: &mut ClientHello, handshake: &[u8]) {
    let cipher_suites_length_offset = CLIENT_HELLO_SESSION_ID_OFFSET + 1 + hello.session_id.len();
    let cipher_suites_length = take_u16(handshake, cipher_suites_length_offset);
    hello.cipher_suites = handshake[cipher_suites_length_offset + 2
        ..cipher_suites_length_offset + 2 + cipher_suites_length as usize]
        .chunks(2)
        .map(|x| take_u16(x, 0))
        .collect();

    let compression_methods_length_offset =
        cipher_suites_length_offset + 2 + cipher_suites_length as usize;
    let compression_methods_length = handshake[compression_methods_length_offset];

    let extensions_offset =
        compression_methods_length_offset + 1 + compression_methods_length as usize;
    let extensions_length = take_u16(handshake, extensions_offset);

    let mut offset = extensions_offset;

    cli.log(
        3,
        format!(
            "Parsing cipher suites and SNI extension:
        Record length: {}
        Cipher suites length: {}
        Cipher suites available: {}
        Compression methods length: {}
        Compression methods: {:?}",
            handshake.len(),
            cipher_suites_length,
            hello
                .cipher_suites
                .iter()
                .map(|x| hex::encode(x.to_be_bytes()))
                .collect::<Vec<String>>()
                .join(", "),
            compression_methods_length,
            hex::encode(&handshake[compression_methods_length_offset + 1..extensions_offset]),
        ),
    );
    cli.log(
        3,
        format!(
            "
            Extensions length: {} (@offset {})
            Extensions raw data (hex): {:?})",
            extensions_length,
            extensions_offset,
            hex::encode(&handshake[extensions_offset..])
        ),
    );
    offset += 2;

    while offset < extensions_offset + 2 + extensions_length as usize {
        let extension_type = take_u16(handshake, offset);
        offset += 2;
        let extension_length = take_u16(handshake, offset);
        offset += 2;

        if extension_type == EXTENSION_SNI {
            cli.log(4, "SNI extension found".to_string());
            cli.log(4, format!("Extension length: {}", extension_length));
            cli.log(
                4,
                format!(
                    "Extension data: {:?} (total remaining: {})",
                    &handshake[offset..offset + extension_length as usize],
                    handshake[offset..].len()
                ),
            );

            let server_name_list_length = take_u16(handshake, offset);
            offset += 2;
            let server_name_type = handshake[offset];
            offset += 1;
            let server_name_length = take_u16(handshake, offset);
            offset += 2;

            cli.log(
                4,
                format!(
                    "Server name list length {}. Type={}. Name length={}",
                    server_name_list_length, server_name_type, server_name_length
                ),
            );

            hello.host =
                String::from_utf8_lossy(&handshake[offset..offset + server_name_length as usize])
                    .to_string();
            cli.log(4, format!("Host: {}", hello.host));
            break;
        } else {
            cli.log(
                4,
                format!(
                    "Extension type was: 0x{} (len={})",
                    hex::encode(extension_type.to_be_bytes()),
                    extension_length
                ),
            );
            offset += extension_length as usize;
        }
    }
    cli.log(
        4,
        format!(
            "Out of the loop @ offset {} (total len = {})",
            offset,
            handshake.len()
        ),
    );
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
