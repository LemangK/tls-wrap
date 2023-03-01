use super::cache::SessionCache;
use super::util;
use crate::cache::SessionKey;
use tls_wrap_common::ClientBuilder;
use boring::ssl::{SslSignatureAlgorithm, SslVerifyMode, SslVersion};
use bytes::Bytes;
use parking_lot::Mutex;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::net::SocketAddr;

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
            alpn: tls_wrap_common::default_alpn(),
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
        let mut builder = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())?;
        for pem in &self.root_ca {
            for cert in boring::x509::X509::stack_from_pem(&pem).map_err(|e| io::Error::from(e))? {
                add_cert!(builder.cert_store_mut(), cert);
            }
        }

        if self.load_system_root_ca {
            if let Ok(certs) = crate::native_certs::load_native_certs() {
                for cert in certs {
                    add_cert!(builder.cert_store_mut(), cert);
                }
            }
        }

        tracing::info!("total load certs: {}", count);

        // Cipher List
        // Doc：https://www.openssl.org/docs/manmaster/man1/openssl-ciphers.html
        builder.set_cipher_list("ALL:!aPSK:!ECDSA+SHA1:!3DES")?;
        // Be equivalent to
        // builder.set_cipher_list("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA")?;

        // Set Algorithm
        builder.set_verify_algorithm_prefs(&[
            SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
            SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
            SslSignatureAlgorithm::RSA_PKCS1_SHA256,
            SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
            SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
            SslSignatureAlgorithm::RSA_PKCS1_SHA384,
            SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
            SslSignatureAlgorithm::RSA_PKCS1_SHA512,
        ])?;

        // Min Tls Version
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        // Enable GREASE
        builder.set_grease_enabled(true);
        // Extension 18
        builder.enable_signed_cert_timestamps();
        // Extension 5
        builder.enable_ocsp_stapling();
        // Compress Algorithm `Brotli`
        unsafe {
            boring_sys::SSL_CTX_add_cert_compression_alg(
                builder.as_ptr(),
                boring_sys::TLSEXT_cert_compression_brotli as u16,
                None,
                Some(util::decompress_ssl_cert),
            );
        }

        // 2. Skip Verify
        if self.skip_verify {
            builder.set_verify(SslVerifyMode::NONE);
        } else {
            builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            {
                if self.load_system_root_ca {
                    let hostname = self.server_name.to_owned();
                    builder.set_verify_callback(
                        SslVerifyMode::PEER,
                        move |passed, store_ref| crate::native_certs::verify_callback(Some(&hostname), passed, store_ref),
                    );
                }
            }
        }

        // 3. ALPN, b"\x02h2\x08http/1.1"
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
        let mut session_cache: Option<Arc<Mutex<SessionCache>>> = None;
        if !self.enable_session_ticket {
            builder.set_options(boring::ssl::SslOptions::NO_TICKET);
        } else {
            let cache = Arc::new(Mutex::new(SessionCache::new()));
            builder.set_session_cache_mode(boring::ssl::SslSessionCacheMode::CLIENT);
            builder.set_new_session_callback({
                let cache = cache.clone();
                move |ssl, session| {
                    if let Some(key) = util::key_index().ok().and_then(|idx| ssl.ex_data(idx)) {
                        cache.lock().insert(key.clone(), session);
                    }
                }
            });
            builder.set_remove_session_callback({
                let cache = cache.clone();
                move |_, session| cache.lock().remove(session)
            });
            session_cache = Some(cache);
        }

        // 4. Client certificate
        if let Some((cert, key)) = self.identity {
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

        Ok(TlsClient {
            connector: builder.build(),
            use_sni: self.enable_sni,
            server_name: self.server_name,
            skip_verify: self.skip_verify,
            session_cache,
        })
    }
}

#[derive(Clone)]
pub struct TlsClient {
    connector: boring::ssl::SslConnector,
    use_sni: bool,
    server_name: String,
    skip_verify: bool,
    session_cache: Option<Arc<Mutex<SessionCache>>>,
}

impl TlsClient {
    pub async fn connect_with_session<IO>(
        &self,
        stream: IO,
        mut key: Option<SocketAddr>,
    ) -> io::Result<TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let mut configuration = self.connector.configure()?;
        if let Some(key) = key.take() {
            self.set_session(&mut configuration, SessionKey(key))?;
        }
        util::add_application_settings(&configuration, "h2", "h2")?;
        configuration.set_use_server_name_indication(self.use_sni);
        configuration.set_verify_hostname(!self.skip_verify);
        let tls_stream = tokio_boring::connect(configuration, self.server_name.as_str(), stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        Ok(TlsStream { inner: tls_stream })
    }

    pub async fn connect<IO>(&self, stream: IO) -> io::Result<TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_with_session(stream, None).await
    }

    fn set_session(
        &self,
        conf: &mut boring::ssl::ConnectConfiguration,
        key: SessionKey,
    ) -> io::Result<()> {
        if let Some(cache) = &self.session_cache {
            if let Some(session) = cache.lock().get(&key) {
                unsafe {
                    conf.set_session(&session)?;
                }
            }
            let idx = util::key_index()?;
            conf.set_ex_data(idx, key);
        }
        Ok(())
    }
}

pub struct TlsStream<IO> {
    inner: tokio_boring::SslStream<IO>,
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

#[cfg(test)]
mod tests {
    use super::TlsClientBuilder;
    use tls_wrap_common::ClientBuilder;
    use bytes::Bytes;
    use std::io::Read;

    #[test]
    fn test_fn1() {
        let mut f = std::fs::File::open("xx.der").unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        let x = boring::x509::X509::stack_from_pem(s.as_bytes()).unwrap();
        for xx in x {
            eprintln!("{:?}", xx);
        }
        let mut builder = TlsClientBuilder::new("www.google.com".into());
        builder.add_certificate(Bytes::copy_from_slice(s.as_bytes()));

        builder.build().unwrap();
    }
}
