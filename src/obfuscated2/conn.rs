use aes::Aes256;
use ctr::Ctr128BE;

#[derive(Clone)]
pub struct Connection {
    pub dc: i32,
    pub encryptor: Ctr128BE<Aes256>,
    pub decryptor: Ctr128BE<Aes256>,
}
