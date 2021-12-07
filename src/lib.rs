mod core;

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

// #[async_trait::async_trait]
// impl crate::core::DnsResolve for DefauleDnsResolve {
//     async fn resolve(&self, domain: String, port: u16) -> std::io::Result<SocketAddr> {
//         log::debug!("resolve {}", domain);

//         format!("{}:{}", domain, port)
//             .to_socket_addrs()?
//             .next()
//             .map_or(
//                 Err(std::io::Error::new(
//                     std::io::ErrorKind::Other,
//                     "Dns resolve failure",
//                 )),
//                 |addr| Ok(addr),
//             )
//     }
// }

#[cfg(test)]
mod tests {
    use futures::AsyncReadExt;
    use smol::{io::AsyncWriteExt, net::TcpListener};

    use crate::core::Socks5Ex;
    use crate::Socks;

    fn init_logger() {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .init();
    }

    #[test]
    fn test_socks5() {
        init_logger();

        smol::block_on(async move {
            match TcpListener::bind("0.0.0.0:8888").await {
                Ok(tcp) => loop {
                    log::debug!("{}", tcp.local_addr().unwrap());
                    let (tcp, addr) = tcp.accept().await.unwrap();

                    log::info!("accpet {}", addr);

                    smol::spawn(async move {
                        match tcp.authenticate(None).await {
                            Ok(socks) => match socks {
                                Socks::Tcp(mut tcp, addr) => {
                                    log::info!("socks5 {}", addr);
                                    let mut buf = Vec::new();
                                    buf.resize(1024, 0);
                                    let n = tcp.read(&mut buf).await.unwrap();
                                    buf.truncate(n);
                                    tcp.write_all(&mut buf).await.unwrap();
                                    tcp.close().await.unwrap();
                                }
                                Socks::Udp(udp) => {
                                    udp.reject().await.unwrap();
                                }
                            },
                            Err(e) => {
                                log::error!("{}", e);
                            }
                        };
                    })
                    .detach()
                },
                Err(e) => {
                    log::error!("{}", e);
                }
            }
        });
    }
}
