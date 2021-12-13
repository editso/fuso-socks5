mod core;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite};

pub use crate::core::*;

#[derive(Default)]
pub struct PasswordAuth(pub String);

#[async_trait::async_trait]
impl<IO> SocksAuth<IO> for PasswordAuth
where
    IO: AsyncRead + Unpin + AsyncWrite + Send + Sync + 'static,
{
    async fn select(&self, _: Vec<Method>) -> Method {
        Method::User
    }

    async fn auth(&self, io: &mut IO, _: Method) -> std::io::Result<()> {
        let mut buf = Vec::new();

        buf.resize(2, 0);

        io.read_exact(&mut buf).await?;

        let username_len = buf[1];

        buf.resize(username_len as usize + 1, 0);

        io.read_exact(&mut buf).await?;

        let password_len = buf[username_len as usize];

        buf.resize(password_len as usize, 0);

        io.read_exact(&mut buf).await?;

        if !buf.eq(self.0.as_bytes()) {
            log::warn!("password error {}", String::from_utf8_lossy(&buf));

            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "socks5 password error",
            ));
        }

        Ok(())
    }
}

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
