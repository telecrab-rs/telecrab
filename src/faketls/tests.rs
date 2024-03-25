#[cfg(test)]
mod tests {
    use crate::{
        cli::Cli,
        faketls::{self, parse_client_hello, record, ClientHello, HANDSHAKE_TYPE_SERVER},
        secret::{self, MTProtoSecret},
    };
    use base64::Engine;
    use hmac::Hmac;
    use hmac::Mac;
    use serde::de::Visitor;
    use sha2::Sha256;

    struct B64String(String);

    impl Into<B64String> for &str {
        fn into(self) -> B64String {
            B64String(self.to_string())
        }
    }

    impl B64String {
        fn try_bytes(self) -> Result<Vec<u8>, base64::DecodeError> {
            base64::prelude::BASE64_STANDARD.decode(self.0.as_bytes())
        }
        fn bytes(self) -> Vec<u8> {
            self.try_bytes().unwrap()
        }
    }

    struct TestCaseStr {
        time: u32,
        random: B64String,
        session_id: B64String,
        host: &'static str,
        cipher_suite: u16,
        full: B64String,
    }

    fn test_cli() -> Cli {
        Cli::new(3)
    }
    fn test_secret() -> MTProtoSecret {
        (secret::MTProtoSecretVisitor {})
            .visit_string::<toml::de::Error>(
                "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
                    .to_string(),
            )
            .unwrap()
    }

    #[test]
    fn test_case_bad_0_fails() {
        let case: TestCaseStr = TestCaseStr {
        time: 1617181365,
        random: "XvCPc3aAbHbhRLv0kUmy6BfPZOGvsused5/HNsKXEPs=".into(),
        session_id: "St2BZ2uHMFn3B2trD1jfdtpjoJOOg6JBeLhFcyCMCq4=".into(),
        host: "storage.googleapis.com",
        cipher_suite: 4867,
        full: "AQAB/AMDXvCPc3aAbHbhRLv0kUmy6BfPZOGvsused5/HNsKXEPsgSt2BZ2uHMFn3B2trD1jfdtpjoJOOg6JBeLhFcyCACq4ANBMDEwETAsAswCvAJMAjwArACcypwDDAL8AowCfAFMATzKgAnQCcAD0APAA1AC/ACMASAAoBAAF//wEAAQAAAAAbABkAABZzdG9yYWdlLmdvb2dsZWFwaXMuY29tABcAAAANABgAFgQDCAQEAQUDAgMIBQgFBQEIBgYBAgEABQAFANAAAAAzdAAAABIAAAAQADAALgJoMgVoMi0xNgVoMi0xNQVoMi0xNAhzcGR5LzMuMQZzcGR5LzMIaHR0cC8xLjEACwACAQAAMwAmACQAHQAgB/7oLx9JElIALsLJS91H2QNyU1H0osKwIUelVndsLyIALQACAQEAKwAJCAMEAwMDAgMBAAoACgAIAB0AFwAYABkAFQChAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()
    };
        let mut payload: Vec<u8> = case.full.bytes();
        let mut handshake = record::TlsRecord::new(
            record::RecordType::Handshake,
            record::Version::TLS10,
            &mut payload,
        );

        assert!(
            parse_client_hello(&test_cli(), &mut handshake, test_secret().key)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_case_good_0_ok() {
        let case: TestCaseStr = TestCaseStr {
            time: 1617181365,
            random: "XvCPc3aAbHbhRLv0kUmy6BfPZOGvsused5/HNsKXEPs=".into(),
            session_id: "St2BZ2uHMFn3B2trD1jfdtpjoJOOg6JBeLhFcyCMCq4=".into(),
            host: "storage.googleapis.com",
            cipher_suite: 4867,
            full: "AQAB/AMDXvCPc3aAbHbhRLv0kUmy6BfPZOGvsused5/HNsKXEPsgSt2BZ2uHMFn3B2trD1jfdtpjoJOOg6JBeLhFcyCMCq4ANBMDEwETAsAswCvAJMAjwArACcypwDDAL8AowCfAFMATzKgAnQCcAD0APAA1AC/ACMASAAoBAAF//wEAAQAAAAAbABkAABZzdG9yYWdlLmdvb2dsZWFwaXMuY29tABcAAAANABgAFgQDCAQEAQUDAgMIBQgFBQEIBgYBAgEABQAFAQAAAAAzdAAAABIAAAAQADAALgJoMgVoMi0xNgVoMi0xNQVoMi0xNAhzcGR5LzMuMQZzcGR5LzMIaHR0cC8xLjEACwACAQAAMwAmACQAHQAgB/7oLx9JElIALsLJS91H2QNyU1H0osKwIUelVndsLyIALQACAQEAKwAJCAMEAwMDAgMBAAoACgAIAB0AFwAYABkAFQChAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()
        };

        check_ok_client_hello(case);
    }

    #[test]
    fn test_case_good_1_ok() {
        let case = TestCaseStr {
                time: 1617181352,
                random: "5V5sSprk/tFIgy+x1BeKNGhLlFkqfggLpgN7GYOA1ro=".into(),
                session_id: "jxr4d6PXPDk+Lwx3WUp9wvj8TGlOxEdrRJ0ydyJ9+H8=".into(),
                host: "storage.googleapis.com",
                cipher_suite: 4867,
                full: "AQAB/AMD5V5sSprk/tFIgy+x1BeKNGhLlFkqfggLpgN7GYOA1rogjxr4d6PXPDk+Lwx3WUp9wvj8TGlOxEdrRJ0ydyJ9+H8ANBMDEwETAsAswCvAJMAjwArACcypwDDAL8AowCfAFMATzKgAnQCcAD0APAA1AC/ACMASAAoBAAF//wEAAQAAAAAbABkAABZzdG9yYWdlLmdvb2dsZWFwaXMuY29tABcAAAANABgAFgQDCAQEAQUDAgMIBQgFBQEIBgYBAgEABQAFAQAAAAAzdAAAABIAAAAQADAALgJoMgVoMi0xNgVoMi0xNQVoMi0xNAhzcGR5LzMuMQZzcGR5LzMIaHR0cC8xLjEACwACAQAAMwAmACQAHQAgrulAaqUdKeVYM0F+pu6on/h6LBpOyzOKG4xFIKcoFk4ALQACAQEAKwAJCAMEAwMDAgMBAAoACgAIAB0AFwAYABkAFQChAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()
        };

        check_ok_client_hello(case);
    }

    fn check_ok_client_hello(case: TestCaseStr) {
        let mut payload: Vec<u8> = case.full.bytes();
        let mut handshake = record::TlsRecord::new(
            record::RecordType::Handshake,
            record::Version::TLS10,
            &mut payload,
        );

        let client_hello = parse_client_hello(&test_cli(), &mut handshake, test_secret().key)
            .unwrap()
            .unwrap();

        assert_eq!(client_hello.time, case.time);
        assert_eq!(client_hello.random, case.random.bytes().as_slice());
        assert_eq!(client_hello.session_id, case.session_id.bytes().as_slice());
        assert_eq!(client_hello.host, case.host);
        assert_eq!(client_hello.cipher_suites[0], case.cipher_suite);
    }

    #[test]
    fn generate_server_hello_should_return_something_reasonable() {
        let user = crate::config::User {
            user_info: "test".to_string(),
            secret: MTProtoSecret::new("storage.googleapis.com"),
        };
        let client_hello = ClientHello {
            user: Some(&user),
            time: 1617181352,
            random: rand::random(),
            session_id: rand::random::<[u8; 32]>().to_vec(),
            host: "example.com".to_string(),
            cipher_suites: vec![4867],
        };

        let mut welcome_packet = Vec::new();
        client_hello.generate_welcome_packet(&mut welcome_packet);

        let welcome_packet_initial = welcome_packet.clone();
        let records = record::TlsRecord::from_bytes_multiple(&welcome_packet_initial);

        assert_eq!(records[0].type_, record::RecordType::Handshake as u8);
        assert_eq!(records[0].version, record::Version::TLS12 as u16);
        // Server Welcome
        assert_eq!(records[0].payload[0], HANDSHAKE_TYPE_SERVER);
        assert_eq!(records.len(), 3);
        assert_eq!(records[1].type_, record::RecordType::ChangeCipherSpec as u8);
        assert_eq!(records[1].version, record::Version::TLS12 as u16);
        assert_eq!(records[1].payload.len(), 1);
        assert_eq!(records[1].payload[0], 1);
        assert_eq!(records[2].type_, record::RecordType::ApplicationData as u8);
        assert_eq!(records[2].version, record::Version::TLS12 as u16);

        let extracted_hash = &welcome_packet[faketls::WELCOME_PACKET_RANDOM_OFFSET
            ..faketls::WELCOME_PACKET_RANDOM_OFFSET + faketls::RANDOM_LENGTH]
            .to_vec();

        let empty_random = faketls::client_hello_empty_random();

        // Recreate payload with empty random
        welcome_packet.splice(
            faketls::WELCOME_PACKET_RANDOM_OFFSET
                ..faketls::WELCOME_PACKET_RANDOM_OFFSET + faketls::RANDOM_LENGTH,
            empty_random,
        );

        println!("{:?}", welcome_packet);

        // Check that the hash matches the extracted one

        // Now we have to calculate the MAC
        let mut mac = Hmac::<Sha256>::new_from_slice(&user.secret.key).unwrap();

        mac.update(&client_hello.random);
        mac.update(&welcome_packet);

        let result = mac.finalize().into_bytes();

        assert_eq!(*extracted_hash, *result);
    }
}
