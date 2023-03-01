use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::collections::VecDeque;
use std::io;

pub fn parse_certs(bs: &[u8]) -> io::Result<VecDeque<X509>> {
    let tls_cert = X509::stack_from_pem(bs)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;
    if tls_cert.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"));
    }
    Ok(VecDeque::from(tls_cert))
}

pub fn parse_keys(bs: &[u8]) -> io::Result<PKey<Private>> {
    if let Ok(result) = PKey::private_key_from_pem(bs) {
        return Ok(result);
    }
    PKey::private_key_from_pkcs8(bs)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}
