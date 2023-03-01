use super::cache::SessionKey;
use boring::error::ErrorStack;
use boring::ex_data::Index;
use boring::pkey::{PKey, Private};
use boring::ssl::Ssl;
use boring::x509::X509;
use once_cell::sync::OnceCell;
use std::collections::VecDeque;
use std::io;

pub fn key_index() -> Result<Index<Ssl, SessionKey>, ErrorStack> {
    static IDX: OnceCell<Index<Ssl, SessionKey>> = OnceCell::new();
    IDX.get_or_try_init(Ssl::new_ex_index).map(|v| *v)
}

pub extern "C" fn decompress_ssl_cert(
    _ssl: *mut boring_sys::SSL,
    out: *mut *mut boring_sys::CRYPTO_BUFFER,
    mut uncompressed_len: usize,
    in_: *const u8,
    in_len: usize,
) -> libc::c_int {
    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let x: *mut *mut u8 = &mut buf;
        let allocated_buffer = boring_sys::CRYPTO_BUFFER_alloc(x, uncompressed_len);
        if buf.is_null() {
            return 0;
        }
        let uncompressed_len_ptr: *mut usize = &mut uncompressed_len;
        if brotli_decompressor::ffi::BrotliDecoderDecompress(in_len, in_, uncompressed_len_ptr, buf)
            as i32
            == 1
        {
            *out = allocated_buffer;
            1
        } else {
            boring_sys::CRYPTO_BUFFER_free(allocated_buffer);
            0
        }
    }
}

pub fn add_application_settings(
    ssl: &boring::ssl::ConnectConfiguration,
    proto: &str,
    setting: &str,
) -> io::Result<()> {
    use foreign_types_shared::ForeignTypeRef;
    use libc::c_int;
    unsafe {
        fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
            if r <= 0 {
                Err(ErrorStack::get())
            } else {
                Ok(r)
            }
        }
        cvt(boring_sys::SSL_add_application_settings(
            ssl.as_ptr(),
            proto.as_ptr(),
            proto.len(),
            setting.as_ptr(),
            setting.len(),
        ) as c_int)
        .map(|_| ())?;
        Ok(())
    }
}

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
