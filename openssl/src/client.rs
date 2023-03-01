use tls_wrap_common::ClientBuilder;
use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use openssl::ssl::SslVerifyMode;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
            alpn: vec![],
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
        #[allow(unused_variables)]
        let mut count: usize = 0;

        macro_rules! add_cert {
            ($store:expr, $cert:expr) => {
                match $store.add_cert($cert) {
                    Ok(_) => {
                        count += 1;
                    }
                    Err(err) => {
                        tracing::info!("add cert failed: {:?}", err);
                    }
                }
            };
        }

        // 1. Certificate
        {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(openssl_probe::init_ssl_cert_env_vars);
        }
        let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())?;

        for pem in &self.root_ca {
            for cert in openssl::x509::X509::stack_from_pem(&pem).map_err(|e| io::Error::from(e))? {
                add_cert!(builder.cert_store_mut(), cert);
            }
        }

        // 2. Skip Verify
        if self.skip_verify {
            builder.set_verify(SslVerifyMode::NONE);
        } else {
            builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        }

        // 3. ALPN
        let res = self
            .alpn
            .iter()
            .map(|a| [&[a.len() as u8], a.as_bytes()].concat())
            .collect::<Vec<Vec<u8>>>()
            .concat();
        if !res.is_empty() {
            builder.set_alpn_protos(&res)?;
        }

        // 4. Session Ticket
        if !self.enable_session_ticket {
            builder.set_options(openssl::ssl::SslOptions::NO_TICKET);
        }

        // 5. Client certificate
        if let Some((cert, key)) = self.identity {
            let mut certs = crate::util::parse_certs(&cert)?;
            let key = crate::util::parse_keys(&key)?;
            if let Some(leaf) = certs.pop_front() {
                builder.set_certificate(leaf.as_ref())?;
            }
            while let Some(chain) = certs.pop_front() {
                builder.add_extra_chain_cert(chain)?;
            }
            builder.set_private_key(key.as_ref())?;
        }

        Ok(TlsClient {
            connector: std::sync::Arc::new(builder.build()),
            use_sni: self.enable_sni,
            server_name: self.server_name,
        })
    }
}

#[derive(Clone)]
pub struct TlsClient {
    connector: std::sync::Arc<openssl::ssl::SslConnector>,
    use_sni: bool,
    server_name: String,
}

impl TlsClient {
    pub async fn connect<IO>(&self, stream: IO) -> io::Result<TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        use {openssl::ssl::Ssl, tokio_openssl::SslStream};

        let mut ssl = Ssl::new(self.connector.context())?;
        if self.use_sni {
            ssl.set_hostname(&self.server_name)?;
        }
        let mut tls_stream = SslStream::new(ssl, stream).unwrap();
        Pin::new(&mut tls_stream)
            .connect()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(TlsStream { inner: tls_stream })
    }
}

pub struct TlsStream<IO> {
    inner: tokio_openssl::SslStream<IO>,
}

impl<IO> TlsStream<IO> {
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.inner.ssl().selected_alpn_protocol()
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
