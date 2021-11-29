use std::{
    fmt::Display,
    io::{Cursor, Read},
    net::{IpAddr, SocketAddr},
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Future};

#[async_trait::async_trait]
pub trait SocksAuth<IO> {
    async fn select(&self, methods: Vec<Method>) -> Method;

    async fn auth(&self, io: &mut IO, method: Method) -> std::io::Result<()>;
}

#[async_trait::async_trait]
pub trait DnsResolve {
    async fn resolve(&self, domain: String, port: u16) -> std::io::Result<SocketAddr>;
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

enum State<IO, T> {
    Handshake(u8, u8),
    Auth(Method),
    ///     ver cmd rsv atype
    Request(u8, u8, u8, u8),
    Err(String),
    Ok(Socks<IO, T>),
}

pub enum Socks<IO, T> {
    Tcp(IO, SocketAddr),
    Udp(IO, T),
}

struct AType;

#[derive(Debug)]
pub struct Forward {
    addr: SocketAddr,
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

    pub fn data(&self)->&Vec<u8>{
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

impl Forward {
    pub fn new(addr: SocketAddr) -> Self {
        Forward { addr }
    }

    pub async fn unpack<Dns>(&self, data: &[u8], dns: &Dns) -> std::io::Result<UdpPack>
    where
        Dns: DnsResolve + Sync + Send + 'static,
    {
        // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |

        let mut cur = Cursor::new(data);

        let _ = cur.get_u16();
        let _ = cur.get_u8();
        let atyp = cur.get_u8();

        let data = {
            let mut len = cur.position();

            if atyp == 0x03 {
                len += 1;
            }

            cur.into_inner()[len as usize..].to_vec()
        };

        let addr = AType::parse(atyp, &data, dns).await?;

        Ok(UdpPack {
            addr,
            data: data[AType::len(atyp)..].to_vec(),
        })
    }
}


impl<IO, T> Display for State<IO, T> {
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

    pub async fn parse<Dns>(atype: u8, buf: &[u8], dns: &Dns) -> std::io::Result<SocketAddr>
    where
        Dns: DnsResolve + Sync + Send + 'static,
    {
        let len = buf.len();
        let mut cur = Cursor::new(buf);

        log::trace!("[socks] parse address {:?}", buf);

        match atype {
            0x01 => Ok(SocketAddr::new(
                IpAddr::V4(cur.get_u32().into()),
                cur.get_u16(),
            )),
            0x04 => Ok(SocketAddr::new(
                IpAddr::V6(cur.get_u128().into()),
                cur.get_u16(),
            )),
            0x03 => {
                let mut domain = Vec::new();

                domain.resize(len - 2, 0);

                cur.read_exact(&mut domain)?;

                let domain = String::from_utf8_lossy(&domain).to_string();
                let port = cur.get_u16();

                log::debug!("[socks] resolve {}:{}", domain, port);

                Ok(dns.resolve(domain, port).await?)
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid address",
            )),
        }
    }
}

impl<T, IO> Socks<IO, T>
where
    IO: AsyncRead + AsyncWrite + Unpin + Clone + Send + Sync + 'static,
{
    pub async fn parse<Auth, U, F, Dns>(
        mut io: IO,
        udp_forward: U,
        auth: &Auth,
        dns_resolve: &Dns,
    ) -> std::io::Result<Self>
    where
        Auth: SocksAuth<IO> + Send + Sync + 'static,
        U: Fn(SocketAddr, Forward) -> F,
        F: Future<Output = std::io::Result<(T, SocketAddr)>>,
        Dns: DnsResolve + Sync + Send + 'static,
    {
        let mut write_buf = BytesMut::new();

        let mut read_buf = BytesMut::new();
        read_buf.resize(2, 0);

        let mut state = State::Handshake(0, 0);

        loop {
            if !read_buf.is_empty() {
                io.read_exact(&mut read_buf).await?;
            }

            match state {
                State::Handshake(ver, _) if ver == 0 && read_buf.len() == 2 => {
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

                    let method = auth
                        .select(
                            read_buf
                                .iter()
                                .map(|e| e.try_into())
                                .collect::<std::io::Result<Vec<Method>>>()?,
                        )
                        .await;

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
                    auth.auth(&mut io, method).await?;

                    read_buf.resize(4, 0);
                    state = State::Request(0, 0, 0, 0);

                    log::debug!("[socks] Auth success");
                }
                State::Request(ver, _, _, _) if ver == 0 && read_buf.len() == 4 => {
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
                State::Request(ver, cmd, rsv, atype) if atype == 0x03 && read_buf.len() == 1 => {
                    let len = read_buf.get_u8();

                    if len == 0 {
                        state = State::Err(String::from("Invalid domain"));
                    } else {
                        log::debug!("[socks] domain_len={}", len);
                        // domian  + port
                        read_buf.resize(len as usize + 2, 0);
                        state = State::Request(ver, cmd, rsv, atype)
                    }
                }
                State::Request(ver, cmd, rsv, atype) => {
                    let addr =
                        if let Ok(addr) = AType::parse(atype, &mut read_buf, dns_resolve).await {
                            match cmd {
                                // connect
                                0x01 => {
                                    state = State::Ok(Socks::Tcp(io.clone(), addr));
                                    Some(addr)
                                }
                                // udp forward
                                0x03 => udp_forward(addr, Forward::new(addr)).await.map_or(
                                    None,
                                    |(o, addr)| {
                                        state = State::Ok(Socks::Udp(io.clone(), o));
                                        Some(addr)
                                    },
                                ),
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

                    let (rep, addr) =
                        addr.map_or((0x05, "0.0.0.0:0".parse().unwrap()), |addr| (0x00, addr));

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
                        std::io::ErrorKind::Other,
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
