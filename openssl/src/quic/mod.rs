mod hkdf;

pub use tls_wrap_common::quic::{Keys, Version, HeaderKey as IHeaderKey, PacketKey as IPacketKey};
use openssl::hash::MessageDigest;
use openssl::symm::Cipher;
use std::io;
use tls_wrap_common::quic::openssl_like::AeadCipher;
use tls_wrap_common::quic::openssl_like::{impls, Hkdf};

struct HkdfImpl();

impl HkdfImpl {
    fn new() -> Self {
        Self()
    }
}

impl Hkdf for HkdfImpl {
    fn extract(&self, key: &[u8], salt: &[u8], out: &mut [u8]) -> io::Result<usize> {
        let n = hkdf::hkdf_extract_in_place(MessageDigest::sha256(), key, salt, out)?;
        Ok(n)
    }

    fn expand(&self, prk: &[u8], info: &[u8], buf: &mut [u8]) -> io::Result<()> {
        hkdf::hkdf_expand(MessageDigest::sha256(), prk, info, buf)?;
        Ok(())
    }
}

struct Aes128GcmCipher(Cipher);

impl Aes128GcmCipher {
    pub fn new() -> Self {
        Self(Cipher::aes_128_gcm())
    }
}

impl AeadCipher for Aes128GcmCipher {
    fn decrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        aad: &[u8],
        data: &[u8],
        tag: &[u8],
    ) -> io::Result<Vec<u8>> {
        let ret = openssl::symm::decrypt_aead(self.0, key, iv, aad, data, tag);
        Ok(ret?)
    }
}

struct Aes128CbcCipher(Cipher);

impl Aes128CbcCipher {
    pub fn new() -> Self {
        Self(Cipher::aes_128_cbc())
    }
}

impl tls_wrap_common::quic::openssl_like::Cipher for Aes128CbcCipher {
    fn block_size(&self) -> usize {
        self.0.block_size()
    }

    fn encrypt(&self, key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> io::Result<Vec<u8>> {
        let ret = openssl::symm::encrypt(self.0.clone(), key, iv, data)?;
        Ok(ret)
    }
}

pub fn quic_client_keys_initial(
    version: &Version,
    dst_conn_id: &[u8],
) -> io::Result<Keys<impls::HeaderKey, impls::PacketKey>> {
    impls::quic_client_keys_initial(
        version,
        dst_conn_id,
        Box::new(HkdfImpl::new()),
        Box::new(Aes128CbcCipher::new()),
        Box::new(Aes128GcmCipher::new()),
    )
}
