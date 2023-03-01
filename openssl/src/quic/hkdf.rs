// From github https://github.com/tomleavy/rust-openssl-hkdf/blob/main/src/hkdf.rs

//! HKDF derivation
use core::ptr;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl_sys as ffi;
use std::os::raw::{c_int, c_uchar};

fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

/// A type used to extract-and-expand using HKDF.
pub struct HkdfDeriver(*mut openssl_sys::EVP_PKEY_CTX);

unsafe impl Sync for HkdfDeriver {}
unsafe impl Send for HkdfDeriver {}

impl HkdfDeriver {
    /// Creates a new `HkdfDeriver` using the provided private key.
    ///
    /// This corresponds to [`EVP_PKEY_derive_init`] followed by [`EVP_PKEY_CTX_set_hkdf_md`].
    ///
    /// [`EVP_PKEY_derive_init`]: https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_derive_init.html
    /// [`EVP_PKEY_CTX_set_hkdf_md`]: https://www.openssl.org/docs/man1.1.0/crypto/EVP_PKEY_CTX_set_hkdf_md.html
    pub fn new(digest: MessageDigest) -> Result<Self, ErrorStack> {
        unsafe {
            cvt_p(openssl_sys::EVP_PKEY_CTX_new_id(
                ffi::EVP_PKEY_HKDF,
                ptr::null_mut(),
            ))
                .map(HkdfDeriver)
                .and_then(|ctx| cvt(openssl_sys::EVP_PKEY_derive_init(ctx.0)).map(|_| ctx))
                .and_then(|ctx| cvt(ffi::EVP_PKEY_CTX_set_hkdf_md(ctx.0, digest.as_ptr())).map(|_| ctx))
        }
    }

    fn set_mode(&mut self, mode: c_int) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set_hkdf_mode(self.0, mode))?;
        }

        Ok(())
    }

    /// Sets the input keying material for HKDF derivation.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set1_hkdf_key`].
    ///
    /// [`EVP_PKEY_CTX_set1_hkdf_key`]: https://www.openssl.org/docs/man1.1.1/crypto/EVP_PKEY_CTX_set1_hkdf_key.html
    pub fn set_key(&mut self, key: &[u8]) -> Result<(), ErrorStack> {
        let len = key.len();
        assert!(len <= c_int::MAX as usize);

        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set1_hkdf_key(
                self.0,
                key.as_ptr() as *mut c_uchar,
                len as c_int,
            ))?;

            Ok(())
        }
    }

    /// Sets the salt value for HKDF derivation.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_set1_hkdf_salt`].
    ///
    /// [`EVP_PKEY_CTX_set1_hkdf_salt`]: https://www.openssl.org/docs/man1.1.1/crypto/EVP_PKEY_CTX_set1_hkdf_salt.html
    pub fn set_salt(&mut self, salt: &[u8]) -> Result<(), ErrorStack> {
        let len = salt.len();
        assert!(len <= c_int::MAX as usize);

        unsafe {
            cvt(ffi::EVP_PKEY_CTX_set1_hkdf_salt(
                self.0,
                salt.as_ptr() as *mut c_uchar,
                len as c_int,
            ))?;

            Ok(())
        }
    }

    /// Appends info bytes for HKDF derivation.
    ///
    /// This corresponds to [`EVP_PKEY_CTX_add1_hkdf_info`].
    ///
    /// # Warning
    ///
    /// The total length of the `info` buffer must not exceed 1024 bytes in length
    ///
    /// [`EVP_PKEY_CTX_add1_hkdf_info`]: https://www.openssl.org/docs/man1.1.1/crypto/EVP_PKEY_CTX_add1_hkdf_info.html
    pub fn add_info(&mut self, info: &[u8]) -> Result<(), ErrorStack> {
        let len = info.len();
        assert!(len <= c_int::MAX as usize);

        unsafe {
            cvt(ffi::EVP_PKEY_CTX_add1_hkdf_info(
                self.0,
                info.as_ptr() as *mut c_uchar,
                len as c_int,
            ))?;

            Ok(())
        }
    }

    fn derive(&mut self, buf: &mut [u8]) -> Result<usize, ErrorStack> {
        unsafe {
            let mut len = buf.len();
            cvt(openssl_sys::EVP_PKEY_derive(
                self.0,
                buf.as_mut_ptr(),
                &mut len,
            ))?;
            Ok(len)
        }
    }

    /// Execute the HKDF key derivation function in expand-only mode
    ///
    /// This corresponds to [`EVP_PKEY_CTX_hkdf_mode`] and [`EVP_PKEY_derive`].
    ///
    /// # Warning
    ///
    /// [`HkdfDeriver::set_key`] must be called before calling this function to avoid errors.
    ///
    /// [`EVP_PKEY_CTX_hkdf_mode`]: https://www.openssl.org/docs/man1.1.1/crypto/EVP_PKEY_CTX_hkdf_mode.html
    /// [`EVP_PKEY_derive`]: https://www.openssl.org/docs/man1.1.1/crypto/EVP_PKEY_derive.html
    pub fn expand(&mut self, buf: &mut [u8]) -> Result<(), ErrorStack> {
        self.set_mode(ffi::EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)?;
        self.derive(buf)?;
        Ok(())
    }

    /// Execute the HKDF key derivation function in extract-only mode
    ///
    /// This corresponds to [`EVP_PKEY_CTX_hkdf_mode`] and [`EVP_PKEY_derive`].
    ///
    /// # Warning
    ///
    /// [`HkdfDeriver::set_key`] must be called before calling this function to avoid errors.
    ///
    /// [`EVP_PKEY_CTX_hkdf_mode`]: https://www.openssl.org/docs/man1.1.1/crypto/EVP_PKEY_CTX_hkdf_mode.html
    /// [`EVP_PKEY_derive`]: https://www.openssl.org/docs/man1.1.1/crypto/EVP_PKEY_derive.html
    pub fn extract(&mut self) -> Result<Vec<u8>, ErrorStack> {
        let mut len = 0;
        self.set_mode(ffi::EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)?;

        unsafe {
            cvt(openssl_sys::EVP_PKEY_derive(
                self.0,
                ptr::null_mut(),
                &mut len,
            ))?;
        }

        let mut buf = vec![0u8; len];
        self.derive(&mut buf)?;
        Ok(buf)
    }

    /// Execute the HKDF key derivation function in extract-only mode
    ///
    /// This corresponds to [`EVP_PKEY_CTX_hkdf_mode`] and [`EVP_PKEY_derive`].
    ///
    /// # Warning
    ///
    /// [`HkdfDeriver::set_key`] must be called before calling this function to avoid errors.
    ///
    /// [`EVP_PKEY_CTX_hkdf_mode`]: https://www.openssl.org/docs/man1.1.1/crypto/EVP_PKEY_CTX_hkdf_mode.html
    /// [`EVP_PKEY_derive`]: https://www.openssl.org/docs/man1.1.1/crypto/EVP_PKEY_derive.html
    pub fn extract_in_place(&mut self, out: &mut [u8]) -> Result<usize, ErrorStack> {
        let mut len = 0;
        self.set_mode(ffi::EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)?;

        unsafe {
            cvt(openssl_sys::EVP_PKEY_derive(
                self.0,
                ptr::null_mut(),
                &mut len,
            ))?;
        }

        self.derive(&mut out[..len])?;
        Ok(len)
    }

    /// Execute the HKDF key derivation function in extract-and-expand mode
    ///
    /// This corresponds to [`EVP_PKEY_CTX_hkdf_mode`] and [`EVP_PKEY_derive`].
    ///
    /// # Warning
    ///
    /// [`HkdfDeriver::set_key`] must be called before calling this function to avoid errors.
    ///
    /// [`EVP_PKEY_CTX_hkdf_mode`]: https://www.openssl.org/docs/man1.1.1/crypto/EVP_PKEY_CTX_hkdf_mode.html
    /// [`EVP_PKEY_derive`]: https://www.openssl.org/docs/man1.1.1/crypto/EVP_PKEY_derive.html
    pub fn extract_and_expand(&mut self, buf: &mut [u8]) -> Result<(), ErrorStack> {
        self.set_mode(ffi::EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND)?;

        self.derive(buf)?;
        Ok(())
    }
}

impl Drop for HkdfDeriver {
    fn drop(&mut self) {
        unsafe {
            openssl_sys::EVP_PKEY_CTX_free(self.0);
        }
    }
}

/// One-shot HKDF expand
pub fn hkdf_expand(
    digest: MessageDigest,
    key: &[u8],
    info: &[u8],
    buf: &mut [u8],
) -> Result<(), ErrorStack> {
    let mut ctx = HkdfDeriver::new(digest)?;
    ctx.set_key(key)?;
    ctx.add_info(info)?;
    ctx.expand(buf)
}

/// One-shot HKDF extract
#[allow(dead_code)]
pub fn hkdf_extract(digest: MessageDigest, key: &[u8], salt: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let mut ctx = HkdfDeriver::new(digest)?;
    ctx.set_key(key)?;
    ctx.set_salt(salt)?;
    ctx.extract()
}

/// One-shot HKDF extract
pub fn hkdf_extract_in_place(digest: MessageDigest, key: &[u8], salt: &[u8], out: &mut [u8]) -> Result<usize, ErrorStack> {
    let mut ctx = HkdfDeriver::new(digest)?;
    ctx.set_key(key)?;
    ctx.set_salt(salt)?;
    ctx.extract_in_place(out)
}

/// One-shot HKDF extract-and-expand
#[allow(dead_code)]
pub fn hkdf(
    digest: MessageDigest,
    key: &[u8],
    salt: &[u8],
    info: &[u8],
    buf: &mut [u8],
) -> Result<(), ErrorStack> {
    let mut ctx = HkdfDeriver::new(digest)?;
    ctx.set_key(key)?;
    ctx.set_salt(salt)?;
    ctx.add_info(info)?;
    ctx.extract_and_expand(buf)
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::{self, FromHex};

    const IKM: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    const SALT: &str = "000102030405060708090a0b0c";
    const INFO: &str = "f0f1f2f3f4f5f6f7f8f9";
    const L: usize = 42;

    const PRK: &str = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";

    const OKM: &str = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                       34007208d5b887185865";

    #[test]
    fn test_hkdf_expand() {
        let ikm = Vec::from_hex(PRK).unwrap();
        let info = Vec::from_hex(INFO).unwrap();
        let mut out = vec![0u8; L];

        hkdf_expand(MessageDigest::sha256(), &ikm, &info, &mut out).unwrap();
        assert_eq!(out, Vec::from_hex(OKM).unwrap());
    }

    #[test]
    fn test_hkdf_extract() {
        let ikm = Vec::from_hex(IKM).unwrap();
        let salt = Vec::from_hex(SALT).unwrap();
        let out = hkdf_extract(MessageDigest::sha256(), &ikm, &salt).unwrap();
        assert_eq!(out, Vec::from_hex(PRK).unwrap());
    }

    #[test]
    fn test_hkdf() {
        let ikm = Vec::from_hex(IKM).unwrap();
        let salt = Vec::from_hex(SALT).unwrap();
        let info = Vec::from_hex(INFO).unwrap();
        let mut out = vec![0u8; L];

        hkdf(MessageDigest::sha256(), &ikm, &salt, &info, &mut out).unwrap();
        assert_eq!(out, Vec::from_hex(OKM).unwrap());
    }

    #[test]
    fn test_hkdf_expand_struct() {
        let ikm = Vec::from_hex(PRK).unwrap();
        let info = Vec::from_hex(INFO).unwrap();
        let mut out = vec![0u8; L];

        let mut hkdf = HkdfDeriver::new(MessageDigest::sha256()).unwrap();
        hkdf.set_key(&ikm).unwrap();
        hkdf.add_info(&info).unwrap();
        hkdf.expand(&mut out).unwrap();
        assert_eq!(out, Vec::from_hex(OKM).unwrap());
    }

    #[test]
    fn test_hkdf_extract_struct() {
        let ikm = Vec::from_hex(IKM).unwrap();
        let salt = Vec::from_hex(SALT).unwrap();

        let mut hkdf = HkdfDeriver::new(MessageDigest::sha256()).unwrap();
        hkdf.set_key(&ikm).unwrap();
        hkdf.set_salt(&salt).unwrap();

        assert_eq!(hkdf.extract().unwrap(), Vec::from_hex(PRK).unwrap());
    }

    #[test]
    fn test_hkdf_expand_and_extract_struct() {
        let ikm = Vec::from_hex(IKM).unwrap();
        let salt = Vec::from_hex(SALT).unwrap();
        let info = Vec::from_hex(INFO).unwrap();
        let mut out = vec![0u8; L];

        let mut hkdf = HkdfDeriver::new(MessageDigest::sha256()).unwrap();
        hkdf.set_key(&ikm).unwrap();
        hkdf.set_salt(&salt).unwrap();
        hkdf.add_info(&info).unwrap();
        hkdf.extract_and_expand(&mut out).unwrap();

        assert_eq!(out, Vec::from_hex(OKM).unwrap());
    }

    #[test]
    fn test_large_info() {
        let too_big = vec![0u8; 1025];
        let mut hkdf = HkdfDeriver::new(MessageDigest::sha256()).unwrap();
        assert!(hkdf.add_info(&too_big).is_err());
    }
}