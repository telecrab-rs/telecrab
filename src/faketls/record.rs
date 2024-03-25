use std::io::{Error, ErrorKind};

#[allow(dead_code)]
#[repr(u8)]
pub enum RecordType {
    ChangeCipherSpec = 0x14,
    Handshake = 0x16,
    ApplicationData = 0x17,
    Alert = 0x15,
}

#[allow(dead_code)]
#[repr(u16)]
pub enum Version {
    TLS10 = 0x0301,
    TLS11 = 0x0302,
    TLS12 = 0x0303,
    TLS13 = 0x0304,
}

#[derive(Debug)]
pub struct TlsRecordFields<'a> {
    pub type_: u8,
    pub version: u16,
    pub length: u16,
    pub payload: &'a [u8],
}
#[derive(Debug)]

pub struct TlsRecord {
    pub bytes: Vec<u8>,
}

impl<'a> From<&'a TlsRecord> for TlsRecordFields<'a> {
    fn from(record: &'a TlsRecord) -> Self {
        TlsRecordFields {
            type_: record.bytes[0],
            version: u16::from_be_bytes([record.bytes[1], record.bytes[2]]),
            length: u16::from_be_bytes([record.bytes[3], record.bytes[4]]),
            payload: &record.bytes[5..],
        }
    }
}

impl From<TlsRecordFields<'_>> for TlsRecord {
    fn from(fields: TlsRecordFields<'_>) -> Self {
        let mut bytes = Vec::new();
        bytes.push(fields.type_);
        bytes.extend_from_slice(&fields.version.to_be_bytes());
        bytes.extend_from_slice(&fields.length.to_be_bytes());
        bytes.extend_from_slice(fields.payload);
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

    pub fn length(&self) -> usize {
        u16::from_be_bytes([self.bytes[3], self.bytes[4]]) as usize
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
