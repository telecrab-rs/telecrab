use std::fmt;

use base64::Engine;
use serde::{de::Visitor, Deserialize, Serialize};
pub const SECRET_KEY_LEN: usize = 16;

#[derive(Clone, Debug)]
pub struct MTProtoSecret {
    // key is an array of SECRET_KEY_LEN bytes
    pub key: [u8; SECRET_KEY_LEN],
    pub host: String,
}

// Create new key from host

impl MTProtoSecret {
    pub fn new(host: &str) -> Self {
        Self {
            key: rand::random(),
            host: host.to_string(),
        }
    }
}

struct MTProtoSecretVisitor;

impl<'de> Visitor<'de> for MTProtoSecretVisitor {
    type Value = MTProtoSecret;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a 1 byte 0xee header followed by 16 bytes containing a key followed by a variable length string that should be a hostname, coded in base64 or hex")
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        // Check if we are dealing with base64 or hex

        // We check for hex by checking that all chars are in the range 0-9 and a-f
        if v.chars().all(|c| c.is_digit(16)) {
            // We are dealing with hex
            // Let's transform the material into a byte array
            let material = hex::decode(v).map_err(serde::de::Error::custom)?;

            self.visit_bytes(&material)
        } else {
            // We are dealing with base64
            // Let's transform the material into a byte array
            let material = base64::prelude::BASE64_STANDARD
                .decode(v.as_bytes())
                .map_err(serde::de::Error::custom)?;

            self.visit_bytes(&material)
        }
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let mut key = [0u8; SECRET_KEY_LEN];

        if v.len() < SECRET_KEY_LEN {
            return Err(serde::de::Error::invalid_length(v.len(), &"16 bytes"));
        }

        // Check that the first byte is 0xee
        if v[0] != 0xee {
            return Err(serde::de::Error::custom("First byte should be 0xee"));
        }

        key.copy_from_slice(&v[1..SECRET_KEY_LEN + 1]);

        // Check that the rest of the bytes are valid utf8
        if let Ok(s) = std::str::from_utf8(&v[SECRET_KEY_LEN + 1..]) {
            let host = s.to_string();
            Ok(MTProtoSecret { key, host })
        } else {
            return Err(serde::de::Error::custom(
                "Invalid utf8 string for host name",
            ));
        }
    }
}

impl<'de> Deserialize<'de> for MTProtoSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_string(MTProtoSecretVisitor)
    }
}

impl Serialize for MTProtoSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl ToString for MTProtoSecret {
    fn to_string(&self) -> String {
        let mut material = Vec::new();
        material.push(0xee);
        material.extend_from_slice(&self.key);
        material.extend_from_slice(self.host.as_bytes());

        // return in hex by convention
        hex::encode(material)
    }
}
