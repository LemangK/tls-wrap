use super::util;
use tls_wrap_common::ClientBuilder;
use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tls_wrap_common::default_alpn;

pub struct TlsClientBuilder {
    server_name: String,
    root_ca: Vec<Bytes>,
    load_system_root_ca: bool,
    skip_verify: bool,
    alpn: Vec<String>,
    enable_session_ticket: bool,
    enable_sni: bool,
    identity: Option<(Bytes, Bytes)>,
}

impl TlsClientBuilder {
    pub fn new(server_name: String) -> Self {
        Self {
            server_name,
            root_ca: vec![],
            load_system_root_ca: false,
            skip_verify: false,
            alpn: default_alpn(),
            enable_session_ticket: true,
            enable_sni: true,
            identity: None,
        }
    }
}

impl ClientBuilder<TlsClient> for TlsClientBuilder {
    fn set_skip_verify(&mut self, skip: bool) -> &mut Self {
        self.skip_verify = skip;
        self
    }

    fn set_session_ticket(&mut self, enable: bool) -> &mut Self {
        self.enable_session_ticket = enable;
        self
    }

    fn set_use_sni(&mut self, enable: bool) -> &mut Self {
        self.enable_sni = enable;
        self
    }

    fn set_alpn(&mut self, alpn: Vec<String>) -> &mut Self {
        self.alpn = alpn;
        self
    }

    fn set_load_system_ca(&mut self, enable: bool) -> &mut Self {
        self.load_system_root_ca = enable;
        self
    }

    fn set_server_name<S: Into<String>>(&mut self, server_name: S) -> &mut Self {
        self.server_name = server_name.into();
        self
    }

    fn add_certificate<C: Into<Bytes>>(&mut self, cert: C) -> &mut Self {
        self.root_ca.push(cert.into());
        self
    }

    fn set_identity<C: Into<Bytes>, K: Into<Bytes>>(&mut self, cert: C, key: K) -> &mut Self {
        self.identity = Some((cert.into(), key.into()));
        self
    }

    fn build(self) -> io::Result<TlsClient> {
        // 1. Certificate
        let mut root_cert_store = rustls::RootCertStore::empty();

        for pem in self.root_ca {
            let mut certs = io::Cursor::new(&pem[..]);
            let (_, ignored) =
                root_cert_store.add_parsable_certificates(&rustls_pemfile::certs(&mut certs)?);
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
                    Ok(certs) => root_cert_store.add_parsable_certificates(
                        &certs.into_iter().map(|cert| cert.0).collect::<Vec<_>>(),
                    ),
                    Err(error) => return Err(error.into()),
                };
            }

            #[cfg(feature = "rustls-webpki-roots")]
            {
                root_cert_store.add_server_trust_anchors(
                    webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|c| {
                        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                            c.subject,
                            c.spki,
                            c.name_constraints,
                        )
                    }),
                )
            }
        }

        macro_rules! auth {
            ($builder:expr) => {
                match self.identity {
                    None => $builder.with_no_client_auth(),
                    Some((cert, key)) => {
                        let certs =
                            util::load_certs(&cert)?;
                        let mut keys =
                            util::load_keys(&key)?;
                        $builder
                            .with_single_cert(certs, keys.remove(0))
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
                    }
                }
            };
        }

        // 2. Skip Verify
        let mut tls_config = if self.skip_verify {
            #[allow(unused_mut)]
            let mut builder = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(std::sync::Arc::new(
                    util::IgnoreServerCertVerifier(),
                ));
            auth!(builder)
        } else {
            #[allow(unused_mut)]
            let mut builder = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_cert_store);
            auth!(builder)
        };

        // 3. ALPN
        if !self.alpn.is_empty() {
            tls_config.alpn_protocols = self
                .alpn
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect::<Vec<Vec<u8>>>()
        }

        // 4. Session Ticket
        tls_config.enable_tickets = self.enable_session_ticket;

        // 5. SNI
        tls_config.enable_sni = self.enable_sni;

        // 7. Server Name
        let server_name =
            rustls::ServerName::try_from(&self.server_name as &str).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("invalid dns name {:?}", self.server_name),
                )
            })?;

        Ok(TlsClient {
            connector: tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config)),
            sni: server_name,
        })
    }
}

#[derive(Clone)]
pub struct TlsClient {
    connector: tokio_rustls::TlsConnector,
    sni: rustls::ServerName,
}

impl TlsClient {
    pub async fn connect<IO>(&self, stream: IO) -> io::Result<TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let tls_stream = self.connector.connect(self.sni.clone(), stream).await?;
        Ok(TlsStream { inner: tls_stream })
    }
}

pub struct TlsStream<IO> {
    inner: tokio_rustls::client::TlsStream<IO>,
}

impl<IO> TlsStream<IO> {
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        let (_, session) = self.inner.get_ref();
        session.alpn_protocol()
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
