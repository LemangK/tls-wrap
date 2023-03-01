mod hkdf;

use boring::hash::MessageDigest;
use boring::symm::Cipher;
use std::io;
use tls_wrap_common::quic::openssl_like::AeadCipher;
use tls_wrap_common::quic::openssl_like::{impls, Hkdf};
pub use tls_wrap_common::quic::{HeaderKey as IHeaderKey, Keys, PacketKey as IPacketKey, Version};

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

struct HkdfImpl();

impl HkdfImpl {
    fn new() -> Self {
        Self()
    }
}

impl Hkdf for HkdfImpl {
    fn extract(&self, key: &[u8], salt: &[u8], out: &mut [u8]) -> io::Result<usize> {
        let n = hkdf::hkdf_extract(MessageDigest::sha256(), key, salt, out)?;
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
        let ret = boring::symm::decrypt_aead(self.0, key, iv, aad, data, tag);
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
        let ret = cipher(self.0.clone(), Mode::Encrypt, key, iv, data)?;
        Ok(ret)
    }
}

fn cipher(
    t: Cipher,
    mode: Mode,
    key: &[u8],
    iv: Option<&[u8]>,
    data: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let mut c = Crypter::new(t, mode, key, iv)?;
    let mut out = vec![0; data.len() + t.block_size()];
    let count = c.update(data, &mut out)?;
    let rest = c.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
}

use boring::error::ErrorStack;
use boring_sys as ffi;
use libc::{c_int, c_uint};
use std::cmp;
use std::ptr;

fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[derive(Copy, Clone)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

pub struct Crypter {
    ctx: *mut ffi::EVP_CIPHER_CTX,
    block_size: usize,
}

unsafe impl Sync for Crypter {}
unsafe impl Send for Crypter {}

impl Crypter {
    /// Creates a new `Crypter`.  The initialisation vector, `iv`, is not necesarry for certain
    /// types of `Cipher`.
    ///
    /// # Panics
    ///
    /// Panics if an IV is required by the cipher but not provided.  Also make sure that the key
    /// and IV size are appropriate for your cipher.
    pub fn new(
        t: Cipher,
        mode: Mode,
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<Crypter, ErrorStack> {
        ffi::init();

        unsafe {
            let ctx = cvt_p(ffi::EVP_CIPHER_CTX_new())?;
            let crypter = Crypter {
                ctx,
                block_size: t.block_size(),
            };

            let mode = match mode {
                Mode::Encrypt => 1,
                Mode::Decrypt => 0,
            };

            cvt(ffi::EVP_CipherInit_ex(
                crypter.ctx,
                t.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                mode,
            ))?;

            assert!(key.len() <= c_int::MAX as usize);
            cvt(ffi::EVP_CIPHER_CTX_set_key_length(
                crypter.ctx,
                key.len() as c_uint,
            ))?;

            let key = key.as_ptr() as *mut _;
            let iv = match (iv, t.iv_len()) {
                (Some(iv), Some(len)) => {
                    if iv.len() != len {
                        assert!(iv.len() <= c_int::MAX as usize);
                        cvt(ffi::EVP_CIPHER_CTX_ctrl(
                            crypter.ctx,
                            ffi::EVP_CTRL_GCM_SET_IVLEN,
                            iv.len() as c_int,
                            ptr::null_mut(),
                        ))?;
                    }
                    iv.as_ptr() as *mut _
                }
                _ => ptr::null_mut(),
            };
            cvt(ffi::EVP_CipherInit_ex(
                crypter.ctx,
                ptr::null(),
                ptr::null_mut(),
                key,
                iv,
                mode,
            ))?;

            Ok(crypter)
        }
    }

    /// Feeds data from `input` through the cipher, writing encrypted/decrypted
    /// bytes into `output`.
    ///
    /// The number of bytes written to `output` is returned. Note that this may
    /// not be equal to the length of `input`.
    ///
    /// # Panics
    ///
    /// Panics for stream ciphers if `output.len() < input.len()`.
    ///
    /// Panics for block ciphers if `output.len() < input.len() + block_size`,
    /// where `block_size` is the block size of the cipher (see `Cipher::block_size`).
    ///
    /// Panics if `output.len() > c_int::max_value()`.
    pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ErrorStack> {
        unsafe {
            let block_size = if self.block_size > 1 {
                self.block_size
            } else {
                0
            };
            assert!(output.len() >= input.len() + block_size);
            assert!(output.len() <= c_int::max_value() as usize);
            let mut outl = output.len() as c_int;
            let inl = input.len() as c_int;

            cvt(ffi::EVP_CipherUpdate(
                self.ctx,
                output.as_mut_ptr(),
                &mut outl,
                input.as_ptr(),
                inl,
            ))?;

            Ok(outl as usize)
        }
    }

    /// Finishes the encryption/decryption process, writing any remaining data
    /// to `output`.
    ///
    /// The number of bytes written to `output` is returned.
    ///
    /// `update` should not be called after this method.
    ///
    /// # Panics
    ///
    /// Panics for block ciphers if `output.len() < block_size`,
    /// where `block_size` is the block size of the cipher (see `Cipher::block_size`).
    pub fn finalize(&mut self, output: &mut [u8]) -> Result<usize, ErrorStack> {
        unsafe {
            if self.block_size > 1 {
                assert!(output.len() >= self.block_size);
            }
            let mut outl = cmp::min(output.len(), c_int::max_value() as usize) as c_int;

            cvt(ffi::EVP_CipherFinal_ex(
                self.ctx,
                output.as_mut_ptr(),
                &mut outl,
            ))?;

            Ok(outl as usize)
        }
    }
}

impl Drop for Crypter {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_CIPHER_CTX_free(self.ctx);
        }
    }
}
