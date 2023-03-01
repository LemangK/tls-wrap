use super::{new_error, X509};
use std::io;

use crate::native_certs::verify::verify_hostname;
use boring::error::ErrorStack;
use boring::stack::StackRef;
use bytes::BytesMut;
use core_foundation::date::CFDate;
use security_framework::certificate::SecCertificate;
use security_framework::policy::SecPolicy;
use security_framework::secure_transport::SslProtocolSide;
use security_framework::trust::SecTrust;
use std::io::Error;

fn cvt(r: libc::c_int) -> Result<libc::c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

pub fn to_der<T>(t: &T, tmp: &mut BytesMut) -> Result<usize, ErrorStack>
where
    T: foreign_types::ForeignTypeRef<CType = boring_sys::X509>,
{
    unsafe {
        let len = cvt(boring_sys::i2d_X509(
            ::foreign_types::ForeignTypeRef::as_ptr(t),
            std::ptr::null_mut(),
        ))?;
        tmp.clear();
        tmp.resize(len as usize, 0);
        cvt(boring_sys::i2d_X509(
            ::foreign_types::ForeignTypeRef::as_ptr(t),
            &mut tmp.as_mut_ptr(),
        ))?;
        Ok(len as usize)
    }
}

pub fn system_verify(hostname: Option<&str>, chain: Option<&StackRef<X509>>) -> io::Result<()> {
    let mut certs = Vec::with_capacity(6);
    let mut tmp = BytesMut::new();

    let chain = chain.ok_or(Error::new(
        io::ErrorKind::Other,
        "x509: empty certificate chain",
    ))?;

    for intermediate in chain {
        let n = to_der(intermediate, &mut tmp)?;
        if let Ok(cert) = SecCertificate::from_der(&tmp[..n]) {
            certs.push(cert);
        }
    }

    let mut trust_obj = SecTrust::create_with_certificates(
        &certs,
        &[SecPolicy::create_ssl(SslProtocolSide::SERVER, hostname)],
    )
    .map_err(new_error)?;
    trust_obj
        .set_trust_verify_date(&CFDate::now())
        .map_err(new_error)?;
    trust_obj.evaluate_with_error().map_err(new_error)?;

    let mut passed: bool = false;
    if let Some(cert) = chain.get(0) {
        if let Some(hostname) = hostname {
            if !verify_hostname(hostname, cert) {
                return Err(Error::new(
                    io::ErrorKind::Other,
                    "x509: verify hostname failed",
                ));
            } else {
                passed = true;
            }
        }
    }

    // let num_certs: isize = trust_obj.certificate_count();
    // for i in 0..num_certs {
    //     // https://stackoverflow.com/questions/68034788/replace-deprecated-sectrustgetcertificateatindex-in-ios-15
    //     #[allow(deprecated)]
    //     if let Some(cert) = trust_obj.certificate_at_index(i) {
    //         unsafe {
    //             let der_data = security_framework_sys::certificate::SecCertificateCopyData(
    //                 cert.as_concrete_TypeRef(),
    //             );
    //             let cf_data = CFData::wrap_under_create_rule(der_data);
    //             let cert = X509::from_der(cf_data.bytes())?;
    //
    //         };
    //         break;
    //     }
    // }

    if !passed {
        // This should _never_ happen, but to be safe
        return Err(Error::new(
            io::ErrorKind::Other,
            "x509: macOS certificate verification internal error",
        ));
    }

    Ok(())
}

pub fn load_native_certs() -> Result<Vec<X509>, Error> {
    Ok(vec![])
    // // The various domains are designed to interact like this:
    // //
    // // "Per-user Trust Settings override locally administered
    // //  Trust Settings, which in turn override the System Trust
    // //  Settings."
    // //
    // // So we collect the certificates in this order; as a map of
    // // their DER encoding to what we'll do with them.  We don't
    // // overwrite existing elements, which mean User settings
    // // trump Admin trump System, as desired.
    //
    // let mut all_certs = HashMap::new();
    //
    // for domain in &[Domain::User, Domain::Admin, Domain::System] {
    //     let ts = TrustSettings::new(*domain);
    //     let iter = ts
    //         .iter()
    //         .map_err(|err| Error::new(ErrorKind::Other, err))?;
    //
    //     for cert in iter {
    //         let der = cert.to_der();
    //
    //         // If there are no specific trust settings, the default
    //         // is to trust the certificate as a root cert.  Weird API but OK.
    //         // The docs say:
    //         //
    //         // "Note that an empty Trust Settings array means "always trust this cert,
    //         //  with a resulting kSecTrustSettingsResult of kSecTrustSettingsResultTrustRoot".
    //         let trusted = ts
    //             .tls_trust_settings_for_certificate(&cert)
    //             .map_err(|err| Error::new(ErrorKind::Other, err))?
    //             .unwrap_or(TrustSettingsForCertificate::TrustRoot);
    //
    //         all_certs.entry(der).or_insert(trusted);
    //     }
    // }
    //
    // let mut certs = Vec::new();
    //
    // // Now we have all the certificates and an idea of whether
    // // to use them.
    // for (der, trusted) in all_certs.drain() {
    //     use TrustSettingsForCertificate::*;
    //     if let TrustRoot | TrustAsRoot = trusted {
    //         certs.push(X509::from_der(&der).map_err(new_error)?);
    //     }
    // }
    //
    // Ok(certs)
}
