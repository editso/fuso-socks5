mod core;
use std::net::{SocketAddr, ToSocketAddrs};

use futures::{AsyncRead, AsyncWrite};

pub use crate::core::*;

#[derive(Default)]
pub struct DefauleDnsResolve {}

#[derive(Default)]
pub struct PasswordAuth {}

#[async_trait::async_trait]
impl<IO> SocksAuth<IO> for PasswordAuth
where
    IO: AsyncRead + AsyncWrite + Send + Sync + 'static,
{
    async fn select(&self, _: Vec<Method>) -> Method {
        Method::No
    }

    async fn auth(&self, _: &mut IO, _: Method) -> std::io::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::core::DnsResolve for DefauleDnsResolve {
    async fn resolve(&self, domain: String, port: u16) -> std::io::Result<SocketAddr> {
        log::debug!("resolve {}", domain);

        format!("{}:{}", domain, port)
            .to_socket_addrs()?
            .next()
            .map_or(
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Dns resolve failure",
                )),
                |addr| Ok(addr),
            )
    }
}

#[cfg(test)]
mod tests {
    use futures::AsyncReadExt;
    use smol::{
        io::AsyncWriteExt,
        net::{TcpListener, UdpSocket},
    };

    use crate::{DefauleDnsResolve, PasswordAuth, Socks};

    fn init_logger() {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .init();
    }

    #[test]
    fn test_socks5() {
        init_logger();

        smol::block_on(async move {
            match TcpListener::bind("127.0.0.1:9005").await {
                Ok(tcp) => loop {
                    match tcp.accept().await {
                        Ok((stream, addr)) => {
                            log::debug!("spawn {}", addr);
                            smol::spawn(async move {
                                match Socks::parse(
                                    stream,
                                    |_, foward| async move {
                                        // let client = UdpSocket::bind("0.0.0.0:0").await?;
                                        // client.connect(addr).await?;

                                        let udp = UdpSocket::bind("0.0.0.0:0").await?;
                                        log::debug!("listen: {}", udp.local_addr().unwrap());
                                        let s = udp.clone();

                                        smol::spawn(async move {
                                            let mut buffer = Vec::new();
                                            buffer.resize(1024, 0);
                                            let (n, addr) = s.recv_from(&mut buffer).await.unwrap();
                                            buffer.truncate(n);

                                            match foward
                                                .unpack(&buffer, &DefauleDnsResolve::default())
                                                .await
                                            {
                                                Ok(pack) => {
                                                    match UdpSocket::bind("0.0.0.0:0").await {
                                                        Ok(client) => {
                                                            client
                                                                .connect(pack.addr())
                                                                .await
                                                                .unwrap();

                                                            log::debug!(
                                                                "udp data {:?}",
                                                                pack.data()
                                                            );

                                                            client.send(pack.data()).await.unwrap();

                                                            let mut buffer = Vec::new();
                                                            buffer.resize(1024, 0);
                                                            let n = client
                                                                .recv(&mut buffer)
                                                                .await
                                                                .unwrap();
                                                            buffer.truncate(n);

                                                            let pack = pack.pack(&buffer);
                                                            s.send_to(&pack, addr).await.unwrap();

                                                            log::debug!("forward {:?}", buffer);
                                                        }
                                                        Err(e) => {
                                                            log::debug!("{}", e)
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    log::debug!("{:?}", e)
                                                }
                                            }
                                        })
                                        .detach();

                                        Ok((udp.clone(), udp.local_addr().unwrap()))
                                    },
                                    &PasswordAuth::default(),
                                    &DefauleDnsResolve::default(),
                                )
                                .await
                                {
                                    Ok(socks) => match socks {
                                        Socks::Tcp(mut tcp, _) => {
                                            let mut buf = Vec::new();
                                            buf.resize(1024, 0);
                                            let n = tcp.read(&mut buf).await.unwrap();

                                            buf.truncate(n);

                                            log::debug!("resp {:?}", String::from_utf8_lossy(&buf));

                                            let _ = tcp.write(&buf).await;
                                        }
                                        Socks::Udp(mut tcp, _) => loop {
                                            let mut buf = Vec::new();
                                            buf.resize(1, 0);

                                            let _ = tcp.read(&mut buf).await;

                                            log::debug!("disconnect");
                                            break;
                                        },
                                    },
                                    Err(_) => {}
                                }
                            })
                            .detach();
                        }
                        Err(_) => {}
                    }
                },
                Err(_) => {}
            }
        });
    }
}
