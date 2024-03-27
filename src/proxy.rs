use crate::{
    cli::Cli,
    config::Config,
    faketls::{self, conn::FakeTlsStream},
    obfuscated2,
    telegram::{self, is_known_dc},
    tokio_utils::SocketWithAddr,
};

use crate::tokio_utils::HasPeerAddr;
use futures::future::FutureExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::broadcast,
};

#[derive(Debug)]
pub enum ProxyEvent {
    TelegramConnectionOpened(std::net::SocketAddr),
    ConnectionOpened(std::net::SocketAddr),
    ConnectionClosed(Option<std::net::SocketAddr>),
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
                        .log_event(ProxyEvent::ConnectionClosed(Some(socket_addr)))
                        .expect("Error logging event");
                }
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
    ) -> Result<obfuscated2::conn::ObfuscatedStream<Box<tokio::net::TcpStream>>, std::io::Error>
    {
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

    async fn relay_data<
        'a,
        TR: AsyncRead + Unpin,
        TW: AsyncWrite + Unpin,
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        TG: SocketWithAddr<'a, TR, TW>,
        CL: SocketWithAddr<'a, CR, CW>,
    >(
        &self,
        tg_socket: &'a mut TG,
        client_socket: &'a mut CL,
    ) -> Result<(), std::io::Error> {
        async fn copy_with_abort<R, W>(
            read: &mut R,
            write: &mut W,
            mut abort: broadcast::Receiver<()>,
        ) -> tokio::io::Result<usize>
        where
            R: AsyncRead + Unpin,
            W: AsyncWrite + Unpin,
        {
            const BUF_SIZE: usize = 4096;
            let mut copied = 0;
            let mut buf = [0u8; BUF_SIZE];
            loop {
                let bytes_read;
                tokio::select! {
                    biased;

                    result = read.read(&mut buf) => {
                        use std::io::ErrorKind::{ConnectionReset, ConnectionAborted};
                        bytes_read = result.or_else(|e| match e.kind() {
                            ConnectionReset | ConnectionAborted => Ok(0),
                            _ => Err(e)
                        })?;
                    },
                    _ = abort.recv() => {
                        break;
                    }
                }
                if bytes_read == 0 {
                    break;
                }

                write.write_all(&buf[..bytes_read]).await?;
                copied += bytes_read;
            }
            Ok(copied)
        }
        async fn wrap_abort<T>(
            cancel: &broadcast::Sender<()>,
            task: impl futures::Future<Output = T>,
        ) -> T {
            task.then(|r: T| {
                let _ = cancel.send(());
                async { r }
            })
            .await
        }
        let tg_addr = tg_socket.peer_addr().ok();
        let client_addr = client_socket.peer_addr().ok();

        let (mut tg_socket_read, mut tg_socket_write) = tg_socket.split();
        let (mut client_socket_read, mut client_socket_write) = client_socket.split();

        let (cancel, _) = broadcast::channel::<()>(1);
        let (remote_copied, client_copied) = tokio::join! {
            wrap_abort(&cancel, copy_with_abort(&mut tg_socket_read, &mut client_socket_write, cancel.subscribe())),
            wrap_abort(&cancel, copy_with_abort(&mut client_socket_read, &mut tg_socket_write, cancel.subscribe())),
        };

        match client_copied {
            Ok(count) => eprintln!("Transferred {} bytes client -->tg", count),
            Err(e) => eprintln!("Error transferring client --->tg: {:?}", e),
        }

        match remote_copied {
            Ok(count) => eprintln!("Transferred {} bytes client<--- tg", count),
            Err(e) => eprintln!("Error transferring client<--- tg: {:?}", e),
        }

        // If we broke out of the loop, close any open connection
        self.log_event(ProxyEvent::ConnectionClosed(tg_addr))?;
        self.log_event(ProxyEvent::ConnectionClosed(client_addr))?;

        // tg_socket.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::io::{Cursor, Read};
    use std::pin::Pin;

    use super::Proxy;
    use crate::tokio_utils::{HasPeerAddr, Socket, Splittable};
    use tokio::io::{AsyncRead, AsyncWrite};

    struct WithFakePeerAddr<S: Socket>(pub std::net::SocketAddr, pub S);
    impl<S: Socket> AsyncRead for WithFakePeerAddr<S> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().1).poll_read(cx, buf)
        }
    }
    impl<S: Socket> AsyncWrite for WithFakePeerAddr<S> {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().1).poll_write(cx, buf)
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().1).poll_flush(cx)
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().1).poll_shutdown(cx)
        }
    }
    impl<S: Socket> HasPeerAddr for WithFakePeerAddr<S> {
        fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            Ok(self.0)
        }
    }
    impl<'a, S: Socket> Splittable<'a, WithFakePeerAddr<S>, WithFakePeerAddr<S>> for WithFakePeerAddr<S>
    where
        S: Socket + Splittable<'a, S, S>,
    {
        fn split(&'a mut self) -> (WithFakePeerAddr<S>, WithFakePeerAddr<S>) {
            let (a, b) = self.1.split();
            (WithFakePeerAddr(self.0, a), WithFakePeerAddr(self.0, b))
        }
    }

    #[tokio::test]
    async fn test_relay_data_simple() {
        let tg_addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
            9999,
        ));
        let client_addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
            8888,
        ));
        let original_client_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let original_tg_data = vec![9, 10, 11, 12, 13, 14, 15, 16];
        let mut client_frames =
            WithFakePeerAddr(client_addr, Cursor::new(original_client_data.to_vec()));
        let mut telegram_frames = WithFakePeerAddr(tg_addr, Cursor::new(original_tg_data.to_vec()));

        let proxy = Proxy::new(crate::cli::Cli::new(3), crate::config::Config::default());
        proxy
            .relay_data(&mut client_frames, &mut telegram_frames)
            .await
            .expect("Error relaying data");

        // Now the frames should be reversed

        let WithFakePeerAddr(_, mut final_client_data) = client_frames;
        let WithFakePeerAddr(_, mut final_tg_data) = telegram_frames;

        final_client_data.set_position(0);
        final_tg_data.set_position(0);

        assert_eq!(
            final_client_data
                .bytes()
                .collect::<Result<Vec<u8>, std::io::Error>>()
                .unwrap(),
            original_tg_data
        );

        assert_eq!(
            final_tg_data
                .bytes()
                .collect::<Result<Vec<u8>, std::io::Error>>()
                .unwrap(),
            original_client_data
        );
    }
}
