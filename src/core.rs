use std::{
    fmt::Display,
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[async_trait]
pub trait SocksAuth<IO> {
    async fn select(&self, methods: Vec<Method>) -> Method;

    async fn auth(&self, io: &mut IO, method: Method) -> std::io::Result<()>;
}

// #[async_trait]
// pub trait DnsResolve {
//     async fn resolve(&self, domain: String, port: u16) -> std::io::Result<SocketAddr>;
// }

#[async_trait]
pub trait Socks5Ex<T> {
    async fn authenticate(
        self,
        auth: Option<Arc<dyn SocksAuth<T> + Send + Sync + 'static>>,
    ) -> std::io::Result<Socks<T>>;
}

#[derive(Clone, Debug, Copy)]
pub enum Method {
    // no auth
    No,
    /// gssapi
    GSSAPI,
    /// username and password
    User,
    /// iana
    IANA(u8),
    /// private
    Private,
    ///
    NotSupport,
}

enum State<IO> {
    Handshake(u8, u8),
    Auth(Method),
    ///     ver cmd rsv atype
    Request(u8, u8, u8, u8),
    Err(String),
    Ok(Socks<IO>),
}

#[derive(Debug, Clone)]
pub enum Addr {
    Socket(SocketAddr),
    Domain(String, u16),
}

pub enum Socks<IO> {
    // ip地址
    Tcp(IO, Addr),
    // udp转发
    Udp(UdpForward<IO>),
}

struct AType;

#[derive(Debug)]
pub struct UdpForward<Tcp> {
    tcp: Tcp,
    addr: Addr,
}

#[derive(Clone, Debug)]
pub struct UdpPack {
    addr: SocketAddr,
    data: Vec<u8>,
}

impl UdpPack {
    pub fn addr(&self) -> SocketAddr {
        self.addr.clone()
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn pack(&self, data: &[u8]) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u16(0x0);
        buf.put_u8(0x0);

        match self.addr {
            SocketAddr::V4(v4) => {
                buf.put_u8(0x01);
                buf.put_slice(&v4.ip().octets());
                buf.put_u16(v4.port());
            }
            SocketAddr::V6(v6) => {
                buf.put_u8(0x04);
                buf.put_slice(&v6.ip().octets());
                buf.put_u16(v6.port());
            }
        };

        buf.put_slice(data);

        buf.to_vec()
    }
}

impl<Tcp> UdpForward<Tcp> {
    pub fn new(tcp: Tcp, addr: Addr) -> Self {
        UdpForward { tcp, addr }
    }

    // pub async fn unpack<Dns>(&self, data: &[u8], dns: &Dns) -> std::io::Result<UdpPack>
    // where
    //     Dns: DnsResolve + Sync + Send + 'static,
    // {
    //     // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |

    //     let mut cur = Cursor::new(data);

    //     let _ = cur.get_u16();
    //     let _ = cur.get_u8();
    //     let atyp = cur.get_u8();

    //     let data = {
    //         let mut len = cur.position();

    //         if atyp == 0x03 {
    //             len += 1;
    //         }

    //         cur.into_inner()[len as usize..].to_vec()
    //     };

    //     let addr = AType::parse(atyp, &data, dns).await?;

    //     Ok(UdpPack {
    //         addr,
    //         data: data[AType::len(atyp)..].to_vec(),
    //     })
    // }
}

impl<IO> Display for State<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fmt = match self {
            State::Handshake(ver, nmethod) => format!("ver={}, nmethod={}", ver, nmethod),
            State::Auth(m) => format!("{:?}", m),
            State::Request(ver, cmd, rsv, atype) => {
                format!("ver={}, cmd={}, rsv={}, atype={}", ver, cmd, rsv, atype)
            }
            State::Err(e) => e.clone(),
            State::Ok(_) => {
                format!("<Socks>")
            }
        };

        writeln!(f, "{}", fmt)
    }
}

impl TryFrom<&u8> for Method {
    type Error = std::io::Error;

    fn try_from(method: &u8) -> Result<Self, Self::Error> {
        Ok(match *method {
            0x00 => Self::No,
            0x01 => Self::GSSAPI,
            0x02 => Self::User,
            0x80 => Self::Private,
            0xFF => Self::NotSupport,
            m if m >= 0x03 && m <= 0x0A => Self::IANA(m),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid Method",
                ))
            }
        })
    }
}

impl From<Method> for u8 {
    fn from(method: Method) -> Self {
        match method {
            Method::No => 0x00,
            Method::GSSAPI => 0x01,
            Method::User => 0x02,
            Method::IANA(iana) => iana,
            Method::Private => 0x80,
            Method::NotSupport => 0xFF,
        }
    }
}

impl AType {
    pub fn len(atype: u8) -> usize {
        match atype {
            0x01 => 6,  // ipv4 + port
            0x03 => 1,  // domain
            0x04 => 18, // ipv6 + port
            _ => 0,
        }
    }

    pub async fn parse(atype: u8, buf: &[u8]) -> std::io::Result<Addr> {
        let len = buf.len();
        let mut cur = Cursor::new(buf);

        log::trace!("[socks] parse address {:?}", buf);

        match atype {
            0x01 => Ok(Addr::Socket(SocketAddr::new(
                IpAddr::V4(cur.get_u32().into()),
                cur.get_u16(),
            ))),
            0x04 => Ok(Addr::Socket(SocketAddr::new(
                IpAddr::V6(cur.get_u128().into()),
                cur.get_u16(),
            ))),
            0x03 => {
                let mut domain = Vec::new();

                domain.resize(len - 2, 0);

                cur.read_exact(&mut domain)?;

                let domain = String::from_utf8_lossy(&domain).to_string();
                let port = cur.get_u16();

                log::debug!("[socks] resolve {}:{}", domain, port);

                Ok(Addr::Domain(domain, port))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid address",
            )),
        }
    }
}

impl<IO> Socks<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Clone + Send + Sync + 'static,
{
    pub async fn parse(
        mut io: IO,
        auth: Option<Arc<dyn SocksAuth<IO> + Send + Sync + 'static>>,
    ) -> std::io::Result<Self> {
        let mut write_buf = BytesMut::new();

        let mut read_buf = BytesMut::new();
        read_buf.resize(2, 0);

        let mut state = State::Handshake(0, 0);

        loop {
            if !read_buf.is_empty() {
                io.read_exact(&mut read_buf).await?;
            }

            match state {
                State::Handshake(0, _) if read_buf.len() == 2 => {
                    let ver = read_buf.get_u8();
                    let nmethod = read_buf.get_u8();

                    if ver != 0x05 {
                        state = State::Err(String::from("Invalid Protocol"));
                    } else {
                        state = State::Handshake(ver, nmethod);

                        read_buf.resize(nmethod as usize, 0);
                    }
                }
                State::Handshake(ver, _) => {
                    log::debug!("[socks] {}", state);

                    let method = {
                        if let Some(auth) = auth.as_ref() {
                            auth.select(
                                read_buf
                                    .iter()
                                    .map(|e| e.try_into())
                                    .collect::<std::io::Result<Vec<Method>>>()?,
                            )
                            .await
                        } else {
                            Method::No
                        }
                    };

                    state = match method {
                        Method::No => {
                            read_buf.resize(4, 0);
                            State::Request(0, 0, 0, 0)
                        }
                        _ => State::Auth(method.clone()),
                    };

                    write_buf.put_u8(ver);
                    write_buf.put_u8(method.into());
                }
                State::Auth(method) => {
                    auth.as_ref().unwrap().auth(&mut io, method).await?;

                    read_buf.resize(4, 0);
                    state = State::Request(0, 0, 0, 0);

                    log::debug!("[socks] Auth success");
                }
                State::Request(0, _, _, _) if read_buf.len() == 4 => {
                    let ver = read_buf.get_u8();
                    if ver != 0x05 {
                        read_buf.clear();
                        state = State::Err(String::from("Invalid Protocol"));
                    } else {
                        let cmd = read_buf.get_u8();
                        let rsv = read_buf.get_u8();
                        let atype = read_buf.get_u8();

                        let len = AType::len(atype);

                        read_buf.resize(len, 0);

                        log::debug!(
                            "[socks] ver={}, cmd={}, rsv={}, atype={}, len={}",
                            ver,
                            cmd,
                            rsv,
                            atype,
                            len
                        );

                        if len > 0 {
                            state = State::Request(ver, cmd, rsv, atype)
                        } else {
                            state = State::Err(String::from("Invalid Address Type"));
                        }
                    }
                }
                State::Request(ver, cmd, rsv, 0x03) if read_buf.len() == 1 => {
                    let len = read_buf.get_u8();

                    if len == 0 {
                        state = State::Err(String::from("Invalid domain"));
                    } else {
                        log::debug!("[socks] domain_len={}", len);
                        // domian  + port
                        read_buf.resize(len as usize + 2, 0);
                        state = State::Request(ver, cmd, rsv, 0x03)
                    }
                }
                State::Request(ver, cmd, rsv, atype) => {
                    let addr = if let Ok(addr) = AType::parse(atype, &mut read_buf).await {
                        match cmd {
                            // connect
                            0x01 => {
                                state = State::Ok(Socks::Tcp(io.clone(), addr.clone()));
                                Some(addr)
                            }
                            // udp forward
                            0x03 => return Ok(Socks::Udp(UdpForward::new(io, addr))),
                            // bind
                            0x02 => {
                                state = State::Err(String::from("Bind not support"));
                                None
                            }
                            _ => {
                                log::debug!("unsupport");
                                None
                            }
                        }
                    } else {
                        None
                    };

                    let rep = addr.map_or(0x05, |_| 0x00);
                    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

                    read_buf.clear();
                    write_buf.clear();
                    write_buf.put_u8(ver);
                    write_buf.put_u8(rep);
                    write_buf.put_u8(rsv);

                    match addr {
                        SocketAddr::V4(v4) => {
                            write_buf.put_u8(0x01);
                            write_buf.put_slice(&v4.ip().octets());
                            write_buf.put_u16(v4.port());
                        }
                        SocketAddr::V6(v6) => {
                            write_buf.put_u8(0x04);
                            write_buf.put_slice(&v6.ip().octets());
                            write_buf.put_u16(v6.port());
                        }
                    }

                    if rep != 0x00 {
                        state = State::Err(String::from("Socks5 create error"));
                    }
                }
                State::Ok(sock) => {
                    break Ok(sock);
                }
                State::Err(e) => {
                    break Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e.to_string(),
                    ))
                }
            };

            if !write_buf.is_empty() {
                log::debug!("[socks] send {:?}", &write_buf);
                io.write_all(&write_buf).await?;
                write_buf.clear();
            }
        }
    }
}

#[async_trait]
impl<T> Socks5Ex<T> for T
where
    T: AsyncRead + AsyncWrite + Unpin + Clone + Send + Sync + 'static,
{
    #[inline]
    async fn authenticate(
        self,
        auth: Option<Arc<dyn SocksAuth<T> + Send + Sync + 'static>>,
    ) -> std::io::Result<Socks<T>> {
        Socks::parse(self, auth).await
    }
}

impl<Tcp> UdpForward<Tcp>
where
    Tcp: AsyncWrite + AsyncRead + Unpin + Send + Sync + 'static,
{
    #[inline]
    pub async fn resolve<Udp>(mut self, addr: SocketAddr) -> std::io::Result<Tcp> {
        let mut buf = BytesMut::new();

        buf.put_slice(&[0x05, 0x00, 0x00]);

        match addr {
            SocketAddr::V4(v4) => {
                buf.put_u8(0x01);
                buf.put_slice(&v4.ip().octets());
                buf.put_u16(v4.port());
            }
            SocketAddr::V6(v6) => {
                buf.put_u8(0x04);
                buf.put_slice(&v6.ip().octets());
                buf.put_u16(v6.port());
            }
        }

        self.tcp.write_all(&buf).await?;

        Ok(self.tcp)
    }

    #[inline]
    pub async fn reject(mut self) -> std::io::Result<()> {
        self.tcp
            .write_all(&[0x05, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .await?;
        Ok(())
    }
}

impl Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{}",
            match self {
                Addr::Socket(addr) => addr.to_string(),
                Addr::Domain(domain, port) => format!("{}:{}", domain, port),
            }
        )
    }
}
