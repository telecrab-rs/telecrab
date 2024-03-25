use crate::{
    cli::Cli,
    config::Config,
    faketls::{self, conn::FakeTlsStream},
    obfuscated2,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Debug)]
pub enum ProxyEvent {
    ConnectionOpened(std::net::SocketAddr),
    ConnectionClosed(std::net::SocketAddr),
    DataReceived(std::net::SocketAddr, Vec<u8>),
    DataSent(std::net::SocketAddr, Vec<u8>),
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
                        .await
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

    pub(crate) async fn log_event(&self, event: ProxyEvent) -> Result<(), std::io::Error> {
        let log_message = format!("{:?}", event);
        self.cli.log(2, log_message);
        Ok(())
    }

    async fn run_proxy_connection(
        &self,
        socket: &mut tokio::net::TcpStream,
        socket_addr: std::net::SocketAddr,
    ) -> Result<(), std::io::Error> {
        self.log_event(ProxyEvent::ConnectionOpened(socket_addr))
            .await?;

        let user = self.faketls_handshake(socket).await?;

        let mut faketls_socket = faketls::wrap_stream(socket);

        let mut ob2conn = self.obfuscated2handshake(user, &mut faketls_socket).await?;

        let mut telegram_conn = self.call_telegram(user, ob2conn.dc).await?;

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
        ))
        .await?;

        let mut server_hello = Vec::new();
        let hello: faketls::ClientHello<'a> = faketls::ClientHello::check(
            client_hello.as_mut_slice(),
            &self.config.users,
            &self.cli,
        )?;

        hello
            .check_valid()?
            // TODO: Implement:  .check_antireplay()?
            .generate_welcome_packet(&mut server_hello);

        socket.write_all(&server_hello).await?;

        self.log_event(ProxyEvent::DataSent(
            socket.peer_addr().unwrap(),
            server_hello[..24].to_vec(),
        ))
        .await?;

        Ok(hello.user())
    }

    async fn obfuscated2handshake(
        &self,
        user: &crate::config::User,
        socket: &mut FakeTlsStream<&mut tokio::net::TcpStream>,
    ) -> Result<obfuscated2::conn::Connection, std::io::Error> {
        obfuscated2::client_handshake(&self, &user.secret.key, socket).await
    }

    async fn call_telegram(
        &self,
        user: &crate::config::User,
        dc: i32,
    ) -> Result<tokio::net::TcpStream, std::io::Error> {
        todo!()
    }

    async fn relay_data(
        &self,
        tg_socket: &mut TcpStream,
        client_socket: &mut obfuscated2::conn::Connection,
    ) -> Result<(), std::io::Error> {
        Ok(())
    }
}
