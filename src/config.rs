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

        Self::default().merge(read_info)
    }

    pub fn default() -> Config {
        Config {
            dc_id: "4".to_string(),
            bind_to: HostPort {
                host: IpAddr::from([0, 0, 0, 0]),
                port: 8443,
            },
            prefer_ip: false,
            allow_dc_fallback: true,
            blocklist_urls: vec![],
            allowlist_urls: vec![],
            update_list_every: Duration::from_secs(3600),
            users: vec![
                User {
                    user_info: "sample_user".to_string(),
                    secret: secret::MTProtoSecret::new("hello-ids.example.com"),
                },
                User {
                    user_info: "sample_user2".to_string(),
                    secret: secret::MTProtoSecret::new("hello-ids.example.com"),
                },
            ],
        }
    }

    pub fn merge(self, other: UserConfig) -> Config {
        Config {
            dc_id: other.dc_id.unwrap_or(self.dc_id),
            bind_to: other.bind_to.unwrap_or(self.bind_to),
            prefer_ip: other.prefer_ip.unwrap_or(self.prefer_ip),
            allow_dc_fallback: other.allow_dc_fallback.unwrap_or(self.allow_dc_fallback),
            blocklist_urls: other.blocklist_urls.unwrap_or(self.blocklist_urls),
            allowlist_urls: other.allowlist_urls.unwrap_or(self.allowlist_urls),
            update_list_every: other.update_list_every.unwrap_or(self.update_list_every),
            users: other.users.unwrap_or(self.users),
        }
    }
}
