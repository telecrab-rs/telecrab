use std::io::{Error, ErrorKind};

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    ChangeCipherSpec = 0x14,
    Handshake = 0x16,
    ApplicationData = 0x17,
    Alert = 0x15,
    Unknown = 0xff,
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Version {
    TLS10 = 0x0301,
    TLS11 = 0x0302,
    TLS12 = 0x0303,
    TLS13 = 0x0304,
}

#[derive(Debug)]
pub struct TlsRecordFields<Payload> {
    pub type_: RecordType,
    pub version: Version,
    pub length: u16,
    pub payload: Payload,
}
#[derive(Debug)]

pub struct TlsRecord {
    pub bytes: Vec<u8>,
}

impl From<u8> for RecordType {
    fn from(byte: u8) -> Self {
        match byte {
            0x14 => RecordType::ChangeCipherSpec,
            0x16 => RecordType::Handshake,
            0x17 => RecordType::ApplicationData,
            0x15 => RecordType::Alert,
            _ => RecordType::Unknown,
        }
    }
}

impl From<u16> for Version {
    fn from(value: u16) -> Self {
        match value {
            0x0301 => Version::TLS10,
            0x0302 => Version::TLS11,
            0x0303 => Version::TLS12,
            0x0304 => Version::TLS13,
            _ => panic!("Unknown version"),
        }
    }
}

#[derive(Debug)]
pub struct Header;
impl<'a> From<&'a [u8]> for Header {
    fn from(_: &'a [u8]) -> Self {
        Header
    }
}

impl<'a, Payload: From<&'a [u8]>> From<&'a TlsRecord> for TlsRecordFields<Payload> {
    fn from(record: &'a TlsRecord) -> Self {
        TlsRecordFields {
            type_: RecordType::from(record.bytes[0]),
            version: Version::from(u16::from_be_bytes([record.bytes[1], record.bytes[2]])),
            length: u16::from_be_bytes([record.bytes[3], record.bytes[4]]),
            payload: Payload::from(&record.bytes[5..]),
        }
    }
}

impl<'a, Payload: Into<&'a [u8]>> From<TlsRecordFields<Payload>> for TlsRecord {
    fn from(fields: TlsRecordFields<Payload>) -> Self {
        let mut bytes = Vec::<u8>::new();
        bytes.push(fields.type_ as u8);
        bytes.extend_from_slice(&(fields.version as u16).to_be_bytes());
        bytes.extend_from_slice(&fields.length.to_be_bytes());
        bytes.extend_from_slice(fields.payload.into());
        Self { bytes }
    }
}

impl TlsRecord {
    pub fn new(type_: RecordType, version: Version, payload: Vec<u8>) -> Self {
        let mut bytes = Vec::new();
        bytes.push(type_ as u8);
        bytes.extend_from_slice(&(version as u16).to_be_bytes());
        bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&payload);
        Self { bytes }
    }

    pub fn clone_with_payload(&self, payload: Vec<u8>) -> Self {
        let mut bytes = Vec::new();
        bytes.push(self.bytes[0]);
        bytes.extend_from_slice(&self.bytes[1..5]);
        bytes.extend_from_slice(&payload);
        Self { bytes }
    }

    pub fn payload(&self) -> &[u8] {
        &self.bytes[5..]
    }

    pub fn header(&self) -> TlsRecordFields<Header> {
        TlsRecordFields::from(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 5 {
            return Err(Error::new(ErrorKind::InvalidData, "Record too short"));
        }

        let length = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;

        if bytes.len() - 5 < length {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Record length does not match payload",
            ));
        }

        Ok(Self {
            bytes: bytes[..5 + length].to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[cfg(test)]
    pub fn from_bytes_multiple(bytes: &[u8]) -> Vec<Self> {
        let mut records = Vec::new();
        let mut offset = 0;

        while offset + 5 < bytes.len() {
            let length = u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]) as usize;

            if bytes.len() - offset < 5 + length {
                break;
            }

            records.push(Self {
                bytes: bytes[offset..offset + 5 + length].to_vec(),
            });
            offset += 5 + length;
        }

        records
    }
}
