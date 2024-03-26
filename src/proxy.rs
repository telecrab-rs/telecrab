use crate::{
    cli::Cli,
    config::Config,
    faketls::{self, conn::FakeTlsStream},
    obfuscated2,
    telegram::{self, is_known_dc},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Debug)]
pub enum ProxyEvent {
    TelegramConnectionOpened(std::net::SocketAddr),
    ConnectionOpened(std::net::SocketAddr),
    ConnectionClosed(std::net::SocketAddr),
    DataReceived(std::net::SocketAddr, Vec<u8>),
    DataSent(std::net::SocketAddr, Vec<u8>),
    DCFallback(i32),
    ConnectedToDC(i32),

    ProxiedDataToClient(std::net::SocketAddr, usize),
    ProxiedDataToTelegram(std::net::SocketAddr, usize),
}

#[derive(Clone)]
pub struct Proxy {
    cli: Cli,
    config: Config,
}

impl Proxy {
    pub fn new(cli: Cli, config: Config) -> Self {
        Self { cli, config }
    }

    pub fn run_loop(&self) {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(self.run_proxy())
            .expect("Error running proxy");
    }

    async fn run_proxy(&self) -> Result<(), std::io::Error> {
        let listener = tokio::net::TcpListener::bind(self.config.bind_to.to_socket_addr()).await?;
        let mut tokio_tasks = Vec::<tokio::task::JoinHandle<()>>::new();

        loop {
            let (mut socket, socket_addr) = listener.accept().await?;

            let subproxy = self.clone();

            tokio_tasks.push(tokio::spawn(async move {
                let result = subproxy
                    .run_proxy_connection(&mut socket, socket_addr)
                    .await;
                if result.is_err() {
                    subproxy.cli.log(1, format!("Error: {:?}", result.err()));

                    subproxy
                        .log_event(ProxyEvent::ConnectionClosed(socket_addr))
                        .expect("Error logging event");
                }
                socket.shutdown().await.expect("Error shutting down socket");
            }));

            // Remove finished tasks from the list
            tokio_tasks = tokio_tasks
                .into_iter()
                .filter_map(|task| if task.is_finished() { None } else { Some(task) })
                .collect();
        }
    }

    pub(crate) fn log_event(&self, event: ProxyEvent) -> Result<(), std::io::Error> {
        let log_message = format!("{:?}", event);
        self.cli.log(2, log_message);
        Ok(())
    }

    async fn run_proxy_connection(
        &self,
        socket: &mut tokio::net::TcpStream,
        socket_addr: std::net::SocketAddr,
    ) -> Result<(), std::io::Error> {
        self.log_event(ProxyEvent::ConnectionOpened(socket_addr))?;

        let user = self.faketls_handshake(socket).await?;

        let mut faketls_socket = faketls::wrap_stream(socket);

        let mut ob2conn = self.obfuscated2handshake(user, &mut faketls_socket).await?;

        let mut telegram_conn = self.call_telegram(ob2conn.dc).await?;
        self.log_event(ProxyEvent::ConnectedToDC(telegram_conn.dc))?;

        self.relay_data(&mut telegram_conn, &mut ob2conn).await
    }

    async fn faketls_handshake<'a>(
        &'a self,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<&crate::config::User, std::io::Error> {
        let mut buffer = [0; 1024];
        let mut client_hello = Vec::new();

        loop {
            let bytes_read = socket.read(&mut buffer).await?;
            client_hello.extend_from_slice(&buffer[..bytes_read]);

            if client_hello.len() > 5 {
                break;
            }
        }

        self.log_event(ProxyEvent::DataReceived(
            socket.peer_addr().unwrap(),
            client_hello.clone(),
        ))?;

        let hello: faketls::ClientHello<'a> = faketls::ClientHello::check(
            client_hello.as_mut_slice(),
            &self.config.users,
            &self.cli,
        )?;

        let server_hello = hello
            .check_valid()?
            // TODO: Implement:  .check_antireplay()?
            .generate_welcome_packet();

        socket.write_all(&server_hello).await?;

        self.log_event(ProxyEvent::DataSent(
            socket.peer_addr().unwrap(),
            server_hello[..24].to_vec(),
        ))?;

        Ok(hello.user())
    }

    async fn obfuscated2handshake<'a>(
        &'a self,
        user: &crate::config::User,
        socket: &'a mut FakeTlsStream<&'a mut tokio::net::TcpStream>,
    ) -> Result<
        obfuscated2::conn::ObfuscatedStream<&'a mut FakeTlsStream<&'a mut TcpStream>>,
        std::io::Error,
    > {
        obfuscated2::client_handshake(&self, &user.secret.key, socket).await
    }

    async fn call_telegram(
        &self,
        mut dc: i32,
    ) -> Result<obfuscated2::conn::ObfuscatedStream<tokio::net::TcpStream>, std::io::Error> {
        let prefer_ip = telegram::known_addresses::PreferIPType::PreferOnlyIPv4;
        if !is_known_dc(dc) && self.config.allow_dc_fallback {
            self.log_event(ProxyEvent::DCFallback(dc))?;
            dc = telegram::get_fallback_dc();
        }
        let socket = telegram::connect_to_telegram(dc, prefer_ip).await?;

        // Do obfuscated2 Server Handshake and return the encrypted connection
        let connection = obfuscated2::server_handshake(&self, socket, dc).await?;
        self.log_event(ProxyEvent::TelegramConnectionOpened(
            connection.peer_addr().unwrap(),
        ))?;
        Ok(connection)
    }

    async fn relay_data(
        &self,
        tg_socket: &mut obfuscated2::conn::ObfuscatedStream<tokio::net::TcpStream>,
        client_socket: &mut obfuscated2::conn::ObfuscatedStream<&mut FakeTlsStream<&mut TcpStream>>,
    ) -> Result<(), std::io::Error> {
        let mut tg_buffer = [0; 1024];
        let mut client_buffer = [0; 1024];
        loop {
            tokio::select! {
                bytes_read = tg_socket.read(&mut tg_buffer) => {
                    let bytes_read = bytes_read?;
                    if bytes_read == 0 {
                        break;
                    }
                    client_socket.write_all(&tg_buffer[..bytes_read]).await?;
                    self.log_event(ProxyEvent::ProxiedDataToClient(tg_socket.peer_addr().unwrap(), bytes_read))?;
                }
                bytes_read = client_socket.read(&mut client_buffer) => {
                    let bytes_read = bytes_read?;
                    if bytes_read == 0 {
                        break;
                    }
                    tg_socket.write_all(&client_buffer[..bytes_read]).await?;
                    self.log_event(ProxyEvent::ProxiedDataToTelegram(client_socket.peer_addr().unwrap(), bytes_read))?;
                }
            }
        }
        // If we broke out of the loop, close any open connection
        self.log_event(ProxyEvent::ConnectionClosed(tg_socket.peer_addr().unwrap()))?;
        self.log_event(ProxyEvent::ConnectionClosed(
            client_socket.peer_addr().unwrap(),
        ))?;

        tg_socket.shutdown().await?;
        Ok(())
    }
}
