#![allow(unused_variables)]
#![allow(dead_code)]

//! rustls-native-certs allows rustls to use the platform's native certificate
//! store when operating as a TLS client.
//!
//! It provides a single function [`load_native_certs()`], which returns a
//! collection of certificates found by reading the platform-native
//! certificate store.
//!
//! If the SSL_CERT_FILE environment variable is set, certificates (in PEM
//! format) are read from that file instead.
//!
//! [`Certificate`] here is just a marker newtype that denotes a DER-encoded
//! X.509 certificate encoded as a `Vec<u8>`.
//!
//! If you want to load these certificates into a `rustls::RootCertStore`,
//! you'll likely want to do something like this:
//!
//! ```no_run
//! let mut roots = rustls::RootCertStore::empty();
//! for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
//!     roots
//!         .add(&rustls::Certificate(cert.0))
//!         .unwrap();
//! }
//! ```

#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
mod unix;

#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
use unix as platform;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod darwin;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use darwin as platform;

mod verify;

use std::io;
use boring::x509::X509;
use std::io::{Error, ErrorKind};

/// Load root certificates found in the platform's native certificate store.
///
/// If the SSL_CERT_FILE environment variable is set, certificates (in PEM
/// format) are read from that file instead.
///
/// This function fails in a platform-specific way, expressed in a `std::io::Error`.
///
/// This function can be expensive: on some platforms it involves loading
/// and parsing a ~300KB disk file.  It's therefore prudent to call
/// this sparingly.
#[inline]
pub fn load_native_certs() -> Result<Vec<X509>, Error> {
    platform::load_native_certs()
}

pub fn verify_callback(
    domain: Option<&str>,
    passed: bool,
    x509_ctx: &boring::x509::X509StoreContextRef,
) -> bool {
    if !passed {
        return false;
    }
    if x509_ctx.current_cert().is_none() {
        return true;
    }
    system_verify(domain, x509_ctx.chain()).is_ok()
}

pub fn system_verify(
    hostname: Option<&str>,
    intermediates: Option<&boring::stack::StackRef<X509>>,
) -> io::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return darwin::system_verify(hostname, intermediates)
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    return Err(io::Error::from(io::ErrorKind::Other))
}

#[allow(dead_code)]
pub(crate) fn new_error<T: ToString>(message: T) -> Error {
    return Error::new(
        ErrorKind::Other,
        format!("Error: {}", message.to_string()),
    );
}