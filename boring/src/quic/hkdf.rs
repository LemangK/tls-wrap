use boring::error::ErrorStack;
use boring::hash::MessageDigest;
use boring_sys as ffi;
use std::os::raw::c_int;

fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

/// One-shot HKDF expand
pub fn hkdf_expand(
    digest: MessageDigest,
    prk: &[u8],
    info: &[u8],
    buf: &mut [u8],
) -> Result<(), ErrorStack> {
    unsafe {
        cvt(ffi::HKDF_expand(
            buf.as_mut_ptr(),
            buf.len(),
            digest.as_ptr(),
            prk.as_ptr(),
            prk.len(),
            info.as_ptr(),
            info.len(),
        ))?;
    }
    Ok(())
}

/// One-shot HKDF extract
pub fn hkdf_extract(
    digest: MessageDigest,
    key: &[u8],
    salt: &[u8],
    out: &mut [u8],
) -> Result<usize, ErrorStack> {
    unsafe {
        let mut out_len = 0;
        cvt(ffi::HKDF_extract(
            out.as_mut_ptr(),
            &mut out_len,
            digest.as_ptr(),
            key.as_ptr(),
            key.len(),
            salt.as_ptr(),
            salt.len(),
        ))?;
        Ok(out_len)
    }
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
        let mut out = vec![0u8; 2048];
        let n = hkdf_extract(MessageDigest::sha256(), &ikm, &salt, &mut out).unwrap();
        assert_eq!(&out[..n], Vec::from_hex(PRK).unwrap());
    }
}
