use std::io::{Error, ErrorKind};

#[repr(u8)]
pub enum RecordType {
    ChangeCipherSpec = 0x14,
    Handshake = 0x16,
    ApplicationData = 0x17,
    Alert = 0x15,
}

#[repr(u16)]
pub enum Version {
    TLS10 = 0x0301,
    TLS11 = 0x0302,
    TLS12 = 0x0303,
    TLS13 = 0x0304,
}

#[derive(Debug)]
pub struct TlsRecord<'a> {
    pub type_: u8,
    pub version: u16,
    length: u16,
    pub payload: &'a [u8],
}

impl<'a> TlsRecord<'a> {
    pub fn new(type_: RecordType, version: Version, payload: &'a [u8]) -> Self {
        Self {
            type_: type_ as u8,
            version: version as u16,
            length: payload.len() as u16,
            payload,
        }
    }

    pub(crate) fn with_payload(&self, payload: &'a [u8]) -> Self {
        Self {
            type_: self.type_,
            version: self.version,
            length: payload.len() as u16,
            payload: payload,
        }
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < 5 {
            return Err(Error::new(ErrorKind::InvalidData, "Record too short"));
        }

        let type_ = bytes[0];
        let version = u16::from_be_bytes([bytes[1], bytes[2]]);
        let length = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;

        if bytes.len() - 5 != length {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Record length does not match payload",
            ));
        }

        Ok(Self {
            type_,
            version,
            length: length as u16,
            payload: &bytes[5..],
        })
    }

    pub fn from_bytes_multiple(bytes: &'a [u8]) -> Vec<Self> {
        let mut records = Vec::new();
        let mut offset = 0;

        while offset + 5 < bytes.len() {
            let type_ = bytes[offset];
            let version = u16::from_be_bytes([bytes[offset + 1], bytes[offset + 2]]);
            let length = u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]) as usize;

            if bytes.len() - offset < 5 + length {
                break;
            }

            records.push(Self {
                type_,
                version,
                length: length as u16,
                payload: &bytes[offset + 5..offset + 5 + length],
            });
            offset += 5 + length;
        }

        records
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.type_);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}
