use aes::Aes256;
use ctr::Ctr128BE;

use super::{make_aes_ctr, HandShakeFrame};

#[derive(Clone, Copy, Debug)]
pub(crate) struct ServerHandshakeFrame(pub(crate) HandShakeFrame);

impl ServerHandshakeFrame {
    pub fn decryptor(&self) -> Ctr128BE<Aes256> {
        let inverted_handshake = self.0.invert();
        make_aes_ctr(inverted_handshake.key(), inverted_handshake.iv())
    }

    pub fn encryptor(&self) -> Ctr128BE<Aes256> {
        make_aes_ctr(self.0.key(), self.0.iv())
    }
}
