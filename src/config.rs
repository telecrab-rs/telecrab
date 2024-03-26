use std::{net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::net::ToSocketAddrs;

use crate::secret;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostPort {
    pub host: IpAddr,
    pub port: u16,
}

impl HostPort {
    pub fn to_socket_addr(&self) -> impl ToSocketAddrs {
        (self.host, self.port)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct User {
    pub user_info: String,
    pub secret: secret::MTProtoSecret,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserConfig {
    pub dc_id: Option<String>,
    pub bind_to: Option<HostPort>,
    pub prefer_ip: Option<bool>,
    pub blocklist_urls: Option<Vec<String>>,
    pub allowlist_urls: Option<Vec<String>>,
    pub update_list_every: Option<Duration>,
    pub users: Option<Vec<User>>,
    pub allow_dc_fallback: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub dc_id: String,
    pub bind_to: HostPort,
    pub prefer_ip: bool,
    pub blocklist_urls: Vec<String>,
    pub allowlist_urls: Vec<String>,
    pub update_list_every: Duration,
    pub users: Vec<User>,
    pub allow_dc_fallback: bool,
}

impl Config {
    pub fn load(file: &str) -> Config {
        let config = std::fs::read_to_string(file).unwrap_or(String::new());
        let read_info = toml::from_str::<UserConfig>(&config).expect("Could not parse config file");

        Config {
            dc_id: read_info.dc_id.unwrap_or("4".to_string()),
            bind_to: read_info.bind_to.unwrap_or(HostPort {
                host: IpAddr::from([0, 0, 0, 0]),
                port: 8443,
            }),
            prefer_ip: read_info.prefer_ip.unwrap_or(false),
            allow_dc_fallback: read_info.allow_dc_fallback.unwrap_or(true),
            blocklist_urls: read_info.blocklist_urls.unwrap_or(vec![]),
            allowlist_urls: read_info.allowlist_urls.unwrap_or(vec![]),
            update_list_every: read_info
                .update_list_every
                .unwrap_or(Duration::from_secs(3600)),
            users: read_info.users.unwrap_or(vec![
                User {
                    user_info: "sample_user".to_string(),
                    secret: secret::MTProtoSecret::new("hello-ids.example.com"),
                },
                User {
                    user_info: "sample_user2".to_string(),
                    secret: secret::MTProtoSecret::new("hello-ids.example.com"),
                },
            ]),
        }
    }
}
