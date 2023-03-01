use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, Error, PrivateKey, ServerName};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::io;

pub struct IgnoreServerCertVerifier();

impl ServerCertVerifier for IgnoreServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
}

pub fn load_certs(reader: &[u8]) -> io::Result<Vec<Certificate>> {
    let mut r = io::Cursor::new(&reader[..]);
    certs(&mut r)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

pub fn load_keys(reader: &[u8]) -> io::Result<Vec<PrivateKey>> {
    let mut r = io::Cursor::new(&reader[..]);
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(&mut r)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())?;
    let mut keys2: Vec<PrivateKey> = rsa_private_keys(&mut r)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())?;
    keys.append(&mut keys2);
    Ok(keys)
}
