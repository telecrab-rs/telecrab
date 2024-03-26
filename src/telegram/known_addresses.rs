use std::net::SocketAddr;

pub struct TelegramAddress(pub SocketAddr);

pub const TELEGRAM_V4_PRODUCTION_ADDRESSES: [TelegramAddress; 6] = [
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(149, 154, 175, 50)),
        443,
    )),
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(149, 154, 167, 51)),
        443,
    )),
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(95, 161, 76, 100)),
        443,
    )),
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(149, 154, 175, 100)),
        443,
    )),
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(149, 154, 167, 91)),
        443,
    )),
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(149, 154, 171, 5)),
        443,
    )),
];

pub const TELEGRAM_V6_PRODUCTION_ADDRESSES: [TelegramAddress; 5] = [
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0xb28, 0xf23d, 0xf001, 0, 0, 0, 0xa,
        )),
        443,
    )),
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x67c, 0x04e8, 0xf002, 0, 0, 0, 0xa,
        )),
        443,
    )),
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0xb28, 0xf23d, 0xf003, 0, 0, 0, 0xa,
        )),
        443,
    )),
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x67c, 0x04e8, 0xf004, 0, 0, 0, 0xa,
        )),
        443,
    )),
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0xb28, 0xf23f, 0xf005, 0, 0, 0, 0xa,
        )),
        443,
    )),
];

pub const TELEGRAM_V4_TEST_ADDRESSES: [TelegramAddress; 3] = [
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(149, 154, 175, 10)),
        443,
    )),
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(149, 154, 167, 40)),
        443,
    )),
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(149, 154, 175, 117)),
        443,
    )),
];

pub const TELEGRAM_V6_TEST_ADDRESSES: [TelegramAddress; 3] = [
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0xb28, 0xf23d, 0xf001, 0, 0, 0, 0xe,
        )),
        443,
    )),
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x67c, 0x04e8, 0xf002, 0, 0, 0, 0xe,
        )),
        443,
    )),
    TelegramAddress(SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0xb28, 0xf23d, 0xf003, 0, 0, 0, 0xe,
        )),
        443,
    )),
];

#[allow(dead_code)]
pub enum PreferIPType {
    PreferOnlyIPv4,
    PreferOnlyIPv6,
    PreferIPv4,
    PreferIPv6,
}

fn _get_pool(
    ip4_pool: &[TelegramAddress],
    ip6_pool: &[TelegramAddress],
    prefer_ip_type: PreferIPType,
    dc: usize,
) -> Vec<SocketAddr> {
    assert!(dc > 0 && dc < 6);
    match prefer_ip_type {
        PreferIPType::PreferOnlyIPv4 => vec![ip4_pool[dc - 1].0],
        PreferIPType::PreferOnlyIPv6 => vec![ip6_pool[dc - 1].0],

        PreferIPType::PreferIPv4 => {
            if dc <= ip6_pool.len() {
                vec![ip4_pool[dc - 1].0, ip6_pool[dc - 1].0]
            } else {
                vec![ip4_pool[dc - 1].0]
            }
        }
        PreferIPType::PreferIPv6 => vec![ip6_pool[dc - 1].0, ip4_pool[dc - 1].0],
    }
}

pub fn get_pool(dc: usize, prefer_ip_type: PreferIPType, test: bool) -> Vec<SocketAddr> {
    if test {
        _get_pool(
            &TELEGRAM_V4_TEST_ADDRESSES,
            &TELEGRAM_V6_TEST_ADDRESSES,
            prefer_ip_type,
            dc,
        )
    } else {
        _get_pool(
            &TELEGRAM_V4_PRODUCTION_ADDRESSES,
            &TELEGRAM_V6_PRODUCTION_ADDRESSES,
            prefer_ip_type,
            dc,
        )
    }
}
