mod constants;
pub mod record;
mod tests;

use self::constants::*;
use crate::{cli::Cli, config::User, safety::constant_time_compare, secret::SECRET_KEY_LEN};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Error, ErrorKind};

use self::record::TlsRecord;
use rand::Rng;
use x25519_dalek::{self, X25519_BASEPOINT_BYTES};

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

    pub fn check<'b>(
        client_hello: &'b mut [u8],
        users: &'a [User],
        cli: &'a Cli,
    ) -> Result<ClientHello<'a>, Error> {
        let mut record = record::TlsRecord::from_bytes(client_hello)?;

        for user in users.iter() {
            let mut client_hello_copy = record.payload.to_vec().clone();
            let client_hello = parse_client_hello(cli, &mut record, user.secret.key)
                .map_err(|str| Error::new(ErrorKind::Other, str))?;

            if client_hello.is_none() {
                continue;
            }
            cli.log(2, format!("User {} logged in", user.user_info));
            return Ok(client_hello.unwrap().with_user(user));
        }
        Err(Error::new(ErrorKind::InvalidData, "User not found"))
    }

    pub fn user(&self) -> &'a User {
        self.user.unwrap()
    }

    fn with_user<'b>(self, user: &'b User) -> ClientHello<'b> {
        ClientHello {
            user: Some(user),
            ..self
        }
    }

    pub fn check_valid(&self) -> Result<&Self, Error> {
        if self.cipher_suites.is_empty() {
            return Err(Error::new(ErrorKind::InvalidData, "No cipher suites"));
        }

        if self.host.is_empty() {
            return Err(Error::new(ErrorKind::InvalidData, "No host"));
        }

        Ok(&self)
    }

    pub fn generate_welcome_packet(&self, buffer: &mut Vec<u8>) {
        let mut welcome_packet = Vec::new();
        self.generate_server_hello(&mut welcome_packet);

        let mut record = TlsRecord::new(
            record::RecordType::Handshake,
            record::Version::TLS12,
            welcome_packet.as_mut_slice(),
        );
        buffer.extend_from_slice(&record.to_bytes());

        let mut payload = [CHANGE_CYPHER_VALUE];
        record = TlsRecord::new(
            record::RecordType::ChangeCipherSpec,
            record::Version::TLS12,
            &mut payload,
        );
        buffer.extend_from_slice(&record.to_bytes());

        let rand_length = 1024 + rand::thread_rng().gen_range(0..3092);
        let mut random_garbage = vec![0u8; rand_length];
        rand::thread_rng().fill(random_garbage.as_mut_slice());

        record = TlsRecord::new(
            record::RecordType::ApplicationData,
            record::Version::TLS12,
            &mut random_garbage,
        );
        buffer.extend_from_slice(&record.to_bytes());

        // Now we have to calculate the MAC
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.user.unwrap().secret.key).unwrap();

        mac.update(&self.random);
        mac.update(&buffer);

        let mac_result = mac.finalize().into_bytes();
        buffer[WELCOME_PACKET_RANDOM_OFFSET..WELCOME_PACKET_RANDOM_OFFSET + mac_result.len()]
            .copy_from_slice(&mac_result);
    }

    pub fn generate_server_hello(&self, server_hello: &mut Vec<u8>) {
        let mut body_buf = Vec::new();
        let mut slice_buf = [0u8; 2];
        let digest: [u8; RANDOM_LENGTH] = client_hello_empty_random();

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

        let mut header: [u8; 4] = (body_buf.len() as u32).to_be_bytes();
        header[0] = HANDSHAKE_TYPE_SERVER;
        server_hello.extend_from_slice(&header);
        server_hello.extend_from_slice(&body_buf);
    }
}

pub fn parse_client_hello<'a>(
    cli: &Cli,
    record: &'a mut TlsRecord,
    secret: [u8; SECRET_KEY_LEN],
) -> Result<Option<ClientHello<'a>>, String> {
    let mut hello = ClientHello::new();

    if record.payload.len() < CLIENT_HELLO_MIN_LENGTH {
        return Err("Client hello too short".to_string());
    }
    if record.payload[0] != HANDSHAKE_TYPE_CLIENT {
        return Err(format!("Invalid handshake type: {}", record.payload[0]).to_string());
    }

    // Bytes are [0, handshake[1], handshake[2], handshake[3]]
    let handshake_size =
        u32::from_be_bytes([0, record.payload[1], record.payload[2], record.payload[3]]) as usize;

    if record.payload.len() - 4 != handshake_size {
        return Err(format!(
            "Invalid handshake size. Manifested={}, real={}",
            hex::encode(handshake_size.to_be_bytes()),
            hex::encode((record.payload.len() - 4).to_be_bytes())
        ));
    }

    let empty_random = client_hello_empty_random();

    hello.random.copy_from_slice(
        &record.payload[CLIENT_HELLO_RANDOM_OFFSET..CLIENT_HELLO_RANDOM_OFFSET + RANDOM_LENGTH],
    );

    let mut payload_with_empty_random = record.payload.to_vec();
    payload_with_empty_random
        [CLIENT_HELLO_RANDOM_OFFSET..CLIENT_HELLO_RANDOM_OFFSET + RANDOM_LENGTH]
        .copy_from_slice(&empty_random);

    let computed_record = record.with_payload(&payload_with_empty_random);

    // mac is calculated for the whole record, not only the payload
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&secret).unwrap();
    mac.update(&computed_record.to_bytes());

    let mut computed_random = mac.finalize().into_bytes();

    for i in 0..RANDOM_LENGTH {
        computed_random[i] ^= hello.random[i];
    }

    if !constant_time_compare(
        &computed_random[..computed_random.len() - 4],
        &computed_record.payload
            [CLIENT_HELLO_RANDOM_OFFSET..CLIENT_HELLO_RANDOM_OFFSET + RANDOM_LENGTH - 4],
    ) {
        // Probably just means that the user did not log in with this secret
        return Ok(None);
    }

    let timestamp = computed_random[RANDOM_LENGTH - 4..RANDOM_LENGTH]
        .try_into()
        .unwrap();
    hello.time = u32::from_le_bytes(timestamp);

    parse_session_id(&mut hello, &record.payload);
    parse_cipher_suite_sni(cli, &mut hello, &record.payload);

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
