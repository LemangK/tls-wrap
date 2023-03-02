use super::util;
use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tls_wrap_common::{default_alpn, read_bs};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone)]
pub struct TlsServer {
    acceptor: tokio_rustls::TlsAcceptor,
}

impl TlsServer {
    pub async fn accept<IO>(&self, stream: IO) -> io::Result<TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let stream = self.acceptor.accept(stream).await?;
        Ok(TlsStream { inner: stream })
    }
}

pub struct TlsServerBuilder {
    identity: (Bytes, Bytes),
    support_alpn: Vec<String>,
    verify_client_certificate: bool,
    root_ca: Vec<Bytes>,
    load_system_root_ca: bool,
}

impl TlsServerBuilder {
    pub fn new(cert_path: &str, key_path: &str) -> io::Result<Self> {
        let certs = read_bs(cert_path)?;
        let keys = read_bs(key_path)?;
        Ok(Self::new_with(certs, keys))
    }

    pub fn new_with<C: Into<Bytes>, K: Into<Bytes>>(cert: C, key: K) -> Self {
        Self {
            identity: (cert.into(), key.into()),
            support_alpn: default_alpn(),
            verify_client_certificate: false,
            root_ca: vec![],
            load_system_root_ca: false,
        }
    }

    pub fn set_alpn(&mut self, alpn: Vec<String>) -> &mut Self {
        self.support_alpn = alpn;
        self
    }

    pub fn set_verify_client_certificate(&mut self, verify: bool) -> &mut Self {
        self.verify_client_certificate = verify;
        self
    }

    pub fn add_certificate<C: Into<Bytes>>(&mut self, cert: C) -> &mut Self {
        self.root_ca.push(cert.into());
        self
    }

    pub fn set_identity<C: Into<Bytes>, K: Into<Bytes>>(&mut self, cert: C, key: K) -> &mut Self {
        self.identity = (cert.into(), key.into());
        self
    }

    pub fn build(self) -> io::Result<TlsServer> {
        #[allow(unused_mut)]
        let mut builder = rustls::ServerConfig::builder().with_safe_defaults();
        let builder = if !self.root_ca.is_empty() {
            use tokio_rustls::rustls::server::AllowAnyAuthenticatedClient;
            let mut roots = rustls::RootCertStore::empty();
            for cert in self.root_ca {
                let mut certs = io::Cursor::new(&cert[..]);
                let (_, ignored) =
                    roots.add_parsable_certificates(&rustls_pemfile::certs(&mut certs)?);
                if ignored != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "CertificateParseError",
                    ));
                }
            }
            if self.load_system_root_ca {
                #[cfg(feature = "rustls-roots")]
                {
                    match rustls_native_certs::load_native_certs() {
                        Ok(certs) => roots.add_parsable_certificates(
                            &certs.into_iter().map(|cert| cert.0).collect::<Vec<_>>(),
                        ),
                        Err(error) => return Err(error.into()),
                    };
                }

                #[cfg(feature = "rustls-webpki-roots")]
                {
                    roots.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
                        |c| {
                            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                                c.subject,
                                c.spki,
                                c.name_constraints,
                            )
                        },
                    ))
                }
            }
            builder.with_client_cert_verifier(AllowAnyAuthenticatedClient::new(roots))
        } else {
            builder.with_no_client_auth()
        };

        let (cert, key) = self.identity;
        let certs = util::load_certs(&cert)?;
        let mut keys = util::load_keys(&key)?;

        let mut config = builder
            .with_single_cert(certs, keys.remove(0))
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

        if !self.support_alpn.is_empty() {
            config.alpn_protocols = self
                .support_alpn
                .iter()
                .map(|s| [&[s.len() as u8], s.as_bytes()].concat())
                .collect::<Vec<Vec<u8>>>()
        }

        Ok(TlsServer {
            acceptor: tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)),
        })
    }
}

pub struct TlsStream<IO> {
    inner: tokio_rustls::server::TlsStream<IO>,
}

impl<IO> TlsStream<IO> {
    #[inline]
    pub fn get_ref(&self) -> &IO {
        let (io, _) = self.inner.get_ref();
        io
    }

    #[inline]
    pub fn peer_certificates(&self, mut f: impl FnMut(&[u8])) {
        let (_, info) = self.inner.get_ref();
        if let Some(cert) = info.peer_certificates() {
            for item in cert {
                f(&item.0[..])
            }
        }
    }
}

impl<IO> AsyncWrite for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<IO> AsyncRead for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}
