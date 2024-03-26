pub const DEFAULT_DC: u8 = 2;
pub const HANDSHAKE_FRAME_LEN: usize = 64;
pub const HANDSHAKE_KEY_LEN: usize = 32;
pub const HANDSHAKE_IV_LEN: usize = 16;
pub const HANDSHAKE_CONNECTION_TYPE_LEN: usize = 4;

pub const HANDSHAKE_FRAME_OFFSET_START: usize = 8;
pub const HANDSHAKE_FRAME_OFFSET_KEY: usize = HANDSHAKE_FRAME_OFFSET_START;
pub const HANDSHAKE_FRAME_OFFSET_IV: usize = HANDSHAKE_FRAME_OFFSET_KEY + HANDSHAKE_KEY_LEN;
pub const HANDSHAKE_FRAME_OFFSET_CONNECTION_TYPE: usize =
    HANDSHAKE_FRAME_OFFSET_IV + HANDSHAKE_IV_LEN;
pub const HANDSHAKE_FRAME_OFFSET_DC: usize =
    HANDSHAKE_FRAME_OFFSET_CONNECTION_TYPE + HANDSHAKE_CONNECTION_TYPE_LEN;

// We only support faketls
pub const HANDSHAKE_CONNECTION_TYPE: [u8; 4] = [0xdd, 0xdd, 0xdd, 0xdd];

#[derive(Clone, Copy, Debug)]
pub(super) struct HandShakeFrame {
    pub data: [u8; HANDSHAKE_FRAME_LEN],
}
