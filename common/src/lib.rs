pub mod quic;

use bytes::Bytes;
use std::io;

pub fn is_path(path: &str) -> bool {
    path_as_bytes(path).is_none()
}

pub fn default_alpn() -> Vec<String> {
    vec!["h2".into(), "http/1.1".into()]
}

fn path_as_bytes(path: &str) -> Option<&[u8]> {
    if path.starts_with("-----") {
        return Some(path.as_bytes());
    }
    if path.starts_with("blob:") {
        return Some(&path.as_bytes()["blob:".len()..]);
    }
    None
}

pub fn read_bs<S: AsRef<str>>(path: S) -> io::Result<Bytes> {
    use io::Read;
    if let Some(bs) = path_as_bytes(path.as_ref()) {
        return Ok(Bytes::copy_from_slice(bs));
    }
    let mut file = std::fs::File::open(std::path::Path::new(path.as_ref()))?;
    let mut content = Vec::new();
    let n = file.read_to_end(&mut content)?;
    content.truncate(n);
    Ok(Bytes::from(content))
}

pub trait ClientBuilder<Out> {
    fn set_skip_verify(&mut self, skip: bool) -> &mut Self;
    fn set_session_ticket(&mut self, enable: bool) -> &mut Self;
    fn set_use_sni(&mut self, enable: bool) -> &mut Self;
    fn set_alpn(&mut self, alpn: Vec<String>) -> &mut Self;
    fn set_load_system_ca(&mut self, enable: bool) -> &mut Self;
    fn set_server_name<S: Into<String>>(&mut self, server_name: S) -> &mut Self;

    fn add_certificate_path<S: AsRef<str>>(&mut self, path: S) -> io::Result<()> {
        let cert = read_bs(path)?;
        self.add_certificate(cert);
        Ok(())
    }

    fn add_certificate<C: Into<Bytes>>(&mut self, cert: C) -> &mut Self;

    /// Set client certificate and private key
    fn set_identity<C: Into<Bytes>, K: Into<Bytes>>(&mut self, cert: C, key: K) -> &mut Self;

    fn set_identity_path<S: AsRef<str>, S2: AsRef<str>>(
        &mut self,
        cert: S,
        key: S2,
    ) -> io::Result<()> {
        let cert = read_bs(cert)?;
        let key = read_bs(key)?;
        self.set_identity(cert, key);
        Ok(())
    }

    fn build(self) -> io::Result<Out>;
}
