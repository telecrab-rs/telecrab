use crate::{cli::Cli, config::Config, faketls};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    async fn log_event(&self, event: ProxyEvent) -> Result<(), std::io::Error> {
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

        self.faketls_handshake(socket).await?;

        self.obfuscated2handshake(socket).await?;

        self.call_telegram(socket);

        self.relay_data(socket).await
    }

    async fn faketls_handshake(
        &self,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<(), std::io::Error> {
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
        faketls::ClientHello::check(&client_hello, &self.config.users, &self.cli)?
            .check_valid()?
            // TODO: Implement:  .check_antireplay()?
            .generate_welcome_packet(&mut server_hello);

        socket.write_all(&server_hello).await?;

        self.log_event(ProxyEvent::DataSent(
            socket.peer_addr().unwrap(),
            server_hello,
        ))
        .await?;

        Ok(())
    }

    async fn obfuscated2handshake(
        &self,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<(), std::io::Error> {
        Ok(())
    }

    async fn call_telegram(
        &self,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<(), std::io::Error> {
        Ok(())
    }

    async fn relay_data(&self, socket: &mut tokio::net::TcpStream) -> Result<(), std::io::Error> {
        Ok(())
    }
}
