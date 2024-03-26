use rand::Rng;
use tokio::net::TcpStream;

use self::known_addresses::PreferIPType;

pub mod known_addresses;

pub async fn connect_to_telegram(
    dc: i32,
    prefer_ip: PreferIPType,
) -> Result<TcpStream, std::io::Error> {
    let tg = known_addresses::get_pool(dc as usize, prefer_ip, false);
    tokio::net::TcpStream::connect(tg.as_slice()).await
}

pub fn is_known_dc(dc: i32) -> bool {
    dc > 0 && dc < 6
}

pub fn get_fallback_dc() -> i32 {
    rand::thread_rng().gen_range(1..5)
}
