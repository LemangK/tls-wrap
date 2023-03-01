use crate::client::TlsStream;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use bytes::Bytes;

#[derive(Clone)]
pub struct TlsServer {}

impl TlsServer {
    pub async fn accept<IO>(&self, _stream: IO) -> io::Result<TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        Err(io::Error::new(io::ErrorKind::Other, "not implemented"))
    }
}

pub struct TlsServerBuilder {}

impl TlsServerBuilder {
    pub fn new(_cert_path: &str, _key_path: &str) -> io::Result<Self> {
        Ok(Self {})
    }

    pub fn new_with<C: Into<Bytes>, K: Into<Bytes>>(_cert: C, _key: K) -> Self {
        Self {}
    }

    pub fn set_alpn(&mut self, _alpn: Vec<String>) -> &mut Self {
        self
    }

    pub fn set_verify_client_certificate(&mut self, _verify: bool) -> &mut Self {
        self
    }

    pub fn add_certificate<C: Into<Bytes>>(&mut self, _cert: C) -> &mut Self {
        self
    }

    pub fn set_identity<C: Into<Bytes>, K: Into<Bytes>>(&mut self, _cert: C, _key: K) -> &mut Self {
        self
    }

    pub fn build(self) -> io::Result<TlsServer> {
        Err(io::Error::new(io::ErrorKind::Other, "not implemented"))
    }
}
