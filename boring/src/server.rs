use super::util;
use boring::ssl::{AlpnError, SslAcceptor, SslMethod, SslOptions, SslVerifyMode};
use boring::x509::store::X509StoreBuilder;
use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tls_wrap_common::{read_bs,default_alpn};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
        let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls_server())?;

        // Support tls1.2, tls1.3, not support tls1.1
        builder.clear_options(SslOptions::NO_TLSV1_3);

        {
            if self.verify_client_certificate {
                builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            } else {
                builder.set_verify(SslVerifyMode::NONE);
            }

            let mut store = X509StoreBuilder::new()?;
            let mut count = 0;

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

            // set client certificate verify store
            for pem in &self.root_ca {
                for cert in
                    boring::x509::X509::stack_from_pem(&pem).map_err(|e| io::Error::from(e))?
                {
                    add_cert!(store, cert);
                }
            }

            if self.load_system_root_ca {
                if let Ok(certs) = crate::native_certs::load_native_certs() {
                    for cert in certs {
                        add_cert!(store, cert);
                    }
                }
            }

            tracing::info!("total load certs: {}", count);
            builder.set_verify_cert_store(store.build())?;
        }

        builder.enable_ocsp_stapling();
        builder.set_grease_enabled(true);
        builder.enable_signed_cert_timestamps();

        // set certificate and key
        {
            let (cert, key) = self.identity;
            let mut certs = util::parse_certs(&cert)?;
            let key = util::parse_keys(&key)?;

            if let Some(leaf) = certs.pop_front() {
                builder.set_certificate(leaf.as_ref())?;
            }
            while let Some(chain) = certs.pop_front() {
                builder.add_extra_chain_cert(chain)?;
            }
            builder.set_private_key(key.as_ref())?;
        }

        // set support alpn
        {
            if self.support_alpn.iter().any(|e| e == "h2") {
                builder.set_alpn_select_callback(|_, protos| {
                    const H2: &[u8] = b"\x02h2";
                    if protos.windows(3).any(|window| window == H2) {
                        Ok(b"h2")
                    } else {
                        Err(AlpnError::NOACK)
                    }
                });
            }
            let res = self
                .support_alpn
                .iter()
                .map(|a| [&[a.len() as u8], a.as_bytes()].concat())
                .collect::<Vec<Vec<u8>>>()
                .concat();
            if !res.is_empty() {
                builder.set_alpn_protos(&res)?;
            }
        }

        let acceptor = builder.build();

        Ok(TlsServer { acceptor })
    }
}

#[derive(Clone)]
pub struct TlsServer {
    acceptor: SslAcceptor,
}

impl TlsServer {
    pub async fn accept<IO>(&self, stream: IO) -> io::Result<TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // MaxVersion or MinVersion not matched, The following errors may occur:
        // 1. TLS handshake failed: cert verification failed - Invalid certificate verification context unexpected EOF
        let stream = tokio_boring::accept(&self.acceptor, stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        Ok(TlsStream { inner: stream })
    }
}

pub struct TlsStream<IO> {
    inner: tokio_boring::SslStream<IO>,
}

impl<IO> TlsStream<IO> {
    #[inline]
    pub fn get_ref(&self) -> &IO {
        self.inner.get_ref()
    }

    #[inline]
    pub fn peer_certificates(&self, mut f: impl FnMut(&[u8])) {
        if let Some(cert) = self.inner.ssl().peer_cert_chain() {
            for item in cert {
                if let Ok(pem) = item.to_pem() {
                    f(&pem[..])
                }
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

#[cfg(test)]
mod tests {
    use super::TlsServerBuilder;
    use tokio::io::AsyncWriteExt;

    fn get_default_tlscert() -> &'static str {
        return "";
    }

    fn get_default_tlskey() -> &'static str {
        return "";
    }

    #[tokio::test]
    async fn test_build() {
        let builder = TlsServerBuilder::new(get_default_tlscert(), get_default_tlskey()).unwrap();
        let server = builder.build().unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:8443")
            .await
            .unwrap();
        loop {
            let (stream, addr) = listener.accept().await.unwrap();
            println!("{:?}", addr);
            let mut tls_stream = server.accept(stream).await.unwrap();
            tls_stream.write_all(b"hello world").await.unwrap();
            break;
        }
    }
}
