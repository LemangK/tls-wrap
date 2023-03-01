use super::util;
use boring::ssl::{AlpnError, SslAcceptor, SslMethod, SslOptions, SslVerifyMode};
use boring::x509::store::X509StoreBuilder;
use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tls_wrap_common::{read_bs,default_alpn};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct TlsServerBuilder {
    identity: (Bytes, Bytes),
    support_alpn: Vec<String>,
    verify_client_certificate: bool,
    root_ca: Vec<Bytes>,
    load_system_root_ca: bool,
}

impl TlsServerBuilder {
    pub fn new(cert_path: &str, key_path: &str) -> io::Result<Self> {
        let certs = read_bs(cert_path)?;
        let keys = read_bs(key_path)?;
        Ok(Self::new_with(certs, keys))
    }

    pub fn new_with<C: Into<Bytes>, K: Into<Bytes>>(cert: C, key: K) -> Self {
        Self {
            identity: (cert.into(), key.into()),
            support_alpn: default_alpn(),
            verify_client_certificate: false,
            root_ca: vec![],
            load_system_root_ca: false,
        }
    }

    pub fn set_alpn(&mut self, alpn: Vec<String>) -> &mut Self {
        self.support_alpn = alpn;
        self
    }

    pub fn set_verify_client_certificate(&mut self, verify: bool) -> &mut Self {
        self.verify_client_certificate = verify;
        self
    }

    pub fn add_certificate<C: Into<Bytes>>(&mut self, cert: C) -> &mut Self {
        self.root_ca.push(cert.into());
        self
    }

    pub fn set_identity<C: Into<Bytes>, K: Into<Bytes>>(&mut self, cert: C, key: K) -> &mut Self {
        self.identity = (cert.into(), key.into());
        self
    }

    pub fn build(self) -> io::Result<TlsServer> {
        // 设置多个域名的方法, 每个配置不同的上下文
        // https://github.com/Termack/jequi/blob/053f3fb87e4e3e5d110993ede6dd14abf04272f9/jequi/src/ssl.rs
        // https://github.com/GreatWizard/gemserv/blob/2388cbda98799dea85a25000a9902e795816e308/src/tls.rs
        let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls_server())?;

        // Support tls1.2, tls1.3, not support tls1.1
        builder.clear_options(SslOptions::NO_TLSV1_3);

        {
            if self.verify_client_certificate {
                builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            } else {
                builder.set_verify(SslVerifyMode::NONE);
            }

            let mut store = X509StoreBuilder::new()?;
            let mut count = 0;

            macro_rules! add_cert {
                ($store:expr, $cert:expr) => {
                    match $store.add_cert($cert) {
                        Ok(_) => {
                            count += 1;
                        }
                        Err(err) => {
                            tracing::info!("add cert failed: {:?}", err);
                        }
                    }
                };
            }

            // set client certificate verify store
            for pem in &self.root_ca {
                for cert in
                    boring::x509::X509::stack_from_pem(&pem).map_err(|e| io::Error::from(e))?
                {
                    add_cert!(store, cert);
                }
            }

            if self.load_system_root_ca {
                if let Ok(certs) = crate::native_certs::load_native_certs() {
                    for cert in certs {
                        add_cert!(store, cert);
                    }
                }
            }

            tracing::info!("total load certs: {}", count);
            builder.set_verify_cert_store(store.build())?;
        }

        builder.enable_ocsp_stapling();
        builder.set_grease_enabled(true);
        builder.enable_signed_cert_timestamps();

        // set certificate and key
        {
            let (cert, key) = self.identity;
            let mut certs = util::parse_certs(&cert)?;
            let key = util::parse_keys(&key)?;

            if let Some(leaf) = certs.pop_front() {
                builder.set_certificate(leaf.as_ref())?;
            }
            while let Some(chain) = certs.pop_front() {
                builder.add_extra_chain_cert(chain)?;
            }
            builder.set_private_key(key.as_ref())?;
        }

        // set support alpn
        {
            if self.support_alpn.iter().any(|e| e == "h2") {
                builder.set_alpn_select_callback(|_, protos| {
                    const H2: &[u8] = b"\x02h2";
                    if protos.windows(3).any(|window| window == H2) {
                        Ok(b"h2")
                    } else {
                        Err(AlpnError::NOACK)
                    }
                });
            }
            let res = self
                .support_alpn
                .iter()
                .map(|a| [&[a.len() as u8], a.as_bytes()].concat())
                .collect::<Vec<Vec<u8>>>()
                .concat();
            if !res.is_empty() {
                builder.set_alpn_protos(&res)?;
            }
        }

        let acceptor = builder.build();

        Ok(TlsServer { acceptor })
    }
}

#[derive(Clone)]
pub struct TlsServer {
    acceptor: SslAcceptor,
}

impl TlsServer {
    pub async fn accept<IO>(&self, stream: IO) -> io::Result<TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // MaxVersion or MinVersion not matched, The following errors may occur:
        // 1. TLS handshake failed: cert verification failed - Invalid certificate verification context unexpected EOF
        let stream = tokio_boring::accept(&self.acceptor, stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        Ok(TlsStream { inner: stream })
    }
}

pub struct TlsStream<IO> {
    inner: tokio_boring::SslStream<IO>,
}

impl<IO> TlsStream<IO> {
    #[inline]
    pub fn get_ref(&self) -> &IO {
        self.inner.get_ref()
    }

    #[inline]
    pub fn peer_certificates(&self, f: impl Fn(&[u8])) {
        if let Some(cert) = self.inner.ssl().peer_cert_chain() {
            for item in cert {
                if let Ok(pem) = item.to_pem() {
                    f(&pem[..])
                }
            }
        }
    }
}

impl<IO> AsyncWrite for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<IO> AsyncRead for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::TlsServerBuilder;
    use tokio::io::AsyncWriteExt;

    fn get_default_tlscert() -> &'static str {
        return "-----BEGIN CERTIFICATE-----\nMIIGhjCCBW6gAwIBAgIIJxHolKoJHOkwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNV\nBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRow\nGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRz\nLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1\ncmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMjIxMTEzMTU0MTUzWhcN\nMjMxMjE1MTU0MTUzWjAXMRUwEwYDVQQDDAwqLnRvc2t5ZS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD8akqZ8rNBgcgY5GAtQrU92IjUyIXg4LE0\nT+lbtrAXXOwiXOMvkjxxvDP97RTi4cf9IwGbmkx6CoQHeGOub9z0fNNWJLmiS5Nt\nCQRRrURNleHH5lU48nVevyxDGjG/V8BlCZ51wWRQmW+5xJYKDdmMyus0JGyv0Gw8\nzBQqhtVakaW6RvyB3zRPDF4IHRR4gcoN3m484nYWevMO60PC7OYK/caYpHakh23s\nONEkjAHAGnt/fDYDemUbwRj521FA6PdeAyoS5tZD6hbZhdIkxXQIe5huwTtZtdiF\nI0wfKX1rF4VZwDte9DpfXImcLCOIaWTkXttDlyB1oGXctrYXs+fzAgMBAAGjggM2\nMIIDMjAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD\nAjAOBgNVHQ8BAf8EBAMCBaAwOAYDVR0fBDEwLzAtoCugKYYnaHR0cDovL2NybC5n\nb2RhZGR5LmNvbS9nZGlnMnMxLTQ3NjIuY3JsMF0GA1UdIARWMFQwSAYLYIZIAYb9\nbQEHFwEwOTA3BggrBgEFBQcCARYraHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5\nLmNvbS9yZXBvc2l0b3J5LzAIBgZngQwBAgEwdgYIKwYBBQUHAQEEajBoMCQGCCsG\nAQUFBzABhhhodHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wQAYIKwYBBQUHMAKGNGh0\ndHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS9nZGlnMi5j\ncnQwHwYDVR0jBBgwFoAUQMK9J47MNIMwojPX+2yz8LQsgM4wIwYDVR0RBBwwGoIM\nKi50b3NreWUuY29tggp0b3NreWUuY29tMB0GA1UdDgQWBBQ4fRcTCrbRqx7THMYW\nDUhQYYdWOzCCAXsGCisGAQQB1nkCBAIEggFrBIIBZwFlAHUA6D7Q2j71BjUy51co\nvIlryQPTy9ERa+zraeF3fW0GvW4AAAGEcaeBYQAABAMARjBEAiBpWzOSzuNV1o8f\nrQ65z662dBONDkX6o3XuOw+2Wh8wwQIge8FTK6sCqmUUtmEvyTAmEdCLY384u0co\nCVxPLfflJrEAdQB6MoxU2LcttiDqOOBSHumEFnAyE4VNO9IrwTpXo1LrUgAAAYRx\np4IUAAAEAwBGMEQCIHKF7OmKUC4i5zWbJWePgqebZUL3eaNzgzL2Rn86FYIVAiAw\nvxi8QLKziPfl2gj/x34Vq3QrhpNOEWc8cQjZ/9KhBAB1ALNzdwfhhFD4Y4bWBanc\nEQlKeS2xZwwLh9zwAw55NqWaAAABhHGngw4AAAQDAEYwRAIgEsv2jirMTf0BRKrP\nxX9ufjr5DgILyM8hEDCmzKDavz4CIBc2KwjPeYhXhMk+0fX6B/0bfk6wbTOCeBA0\n0uoi6XONMA0GCSqGSIb3DQEBCwUAA4IBAQAqBYZS6Bu/EqB+LOUdM1piNRlJWy8h\nKx+V0l/5bGygyEqBmLUaz50fbTGNgdjlPxtGo582N2iMYMQ1SbEuqGCLgYZRQyhD\n13SQqgCfCWjRv5g1yqW6bdxZWKfaBozUHmZRXUK+qkP4H/Pgl5qlRoOrEMFYu/3d\nlXjMpSKZO9RKn5M2u1aRpneS4JrDvGDQhN0Mhg3GZVpo0O9Tmvq/VeoPzVQ1jhCv\n2IINoOImh7+v42CIen9bTDNYWwejP60k+XgubjYPkdTz9GiueSTfXwXrUdw1/Vv3\nkW6ewks+g+MjIOKtY5QOXYB4MC3C+l4btzKWFq6Tv4YQJEzR5Al23Jeg\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCVVMx\nEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoT\nEUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290IENlcnRp\nZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTExMDUwMzA3MDAwMFoXDTMxMDUwMzA3\nMDAwMFowgbQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQH\nEwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UE\nCxMkaHR0cDovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQD\nEypHbyBEYWRkeSBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwggEi\nMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC54MsQ1K92vdSTYuswZLiBCGzD\nBNliF44v/z5lz4/OYuY8UhzaFkVLVat4a2ODYpDOD2lsmcgaFItMzEUz6ojcnqOv\nK/6AYZ15V8TPLvQ/MDxdR/yaFrzDN5ZBUY4RS1T4KL7QjL7wMDge87Am+GZHY23e\ncSZHjzhHU9FGHbTj3ADqRay9vHHZqm8A29vNMDp5T19MR/gd71vCxJ1gO7GyQ5HY\npDNO6rPWJ0+tJYqlxvTV0KaudAVkV4i1RFXULSo6Pvi4vekyCgKUZMQWOlDxSq7n\neTOvDCAHf+jfBDnCaQJsY1L6d8EbyHSHyLmTGFBUNUtpTrw700kuH9zB0lL7AgMB\nAAGjggEaMIIBFjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNV\nHQ4EFgQUQMK9J47MNIMwojPX+2yz8LQsgM4wHwYDVR0jBBgwFoAUOpqFBxBnKLbv\n9r0FQW4gwZTaD94wNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8v\nb2NzcC5nb2RhZGR5LmNvbS8wNQYDVR0fBC4wLDAqoCigJoYkaHR0cDovL2NybC5n\nb2RhZGR5LmNvbS9nZHJvb3QtZzIuY3JsMEYGA1UdIAQ/MD0wOwYEVR0gADAzMDEG\nCCsGAQUFBwIBFiVodHRwczovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkv\nMA0GCSqGSIb3DQEBCwUAA4IBAQAIfmyTEMg4uJapkEv/oV9PBO9sPpyIBslQj6Zz\n91cxG7685C/b+LrTW+C05+Z5Yg4MotdqY3MxtfWoSKQ7CC2iXZDXtHwlTxFWMMS2\nRJ17LJ3lXubvDGGqv+QqG+6EnriDfcFDzkSnE3ANkR/0yBOtg2DZ2HKocyQetawi\nDsoXiWJYRBuriSUBAA/NxBti21G00w9RKpv0vHP8ds42pM3Z2Czqrpv1KrKQ0U11\nGIo/ikGQI31bS/6kA1ibRrLDYGCD+H1QQc7CoZDDu+8CL9IVVO5EFdkKrqeKM+2x\nLXY2JtwE65/3YR8V3Idv7kaWKK2hJn0KCacuBKONvPi8BDAB\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIEfTCCA2WgAwIBAgIDG+cVMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVT\nMSEwHwYDVQQKExhUaGUgR28gRGFkZHkgR3JvdXAsIEluYy4xMTAvBgNVBAsTKEdv\nIERhZGR5IENsYXNzIDIgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwMTAx\nMDcwMDAwWhcNMzEwNTMwMDcwMDAwWjCBgzELMAkGA1UEBhMCVVMxEDAOBgNVBAgT\nB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoTEUdvRGFkZHku\nY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290IENlcnRpZmljYXRlIEF1\ndGhvcml0eSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv3Fi\nCPH6WTT3G8kYo/eASVjpIoMTpsUgQwE7hPHmhUmfJ+r2hBtOoLTbcJjHMgGxBT4H\nTu70+k8vWTAi56sZVmvigAf88xZ1gDlRe+X5NbZ0TqmNghPktj+pA4P6or6KFWp/\n3gvDthkUBcrqw6gElDtGfDIN8wBmIsiNaW02jBEYt9OyHGC0OPoCjM7T3UYH3go+\n6118yHz7sCtTpJJiaVElBWEaRIGMLKlDliPfrDqBmg4pxRyp6V0etp6eMAo5zvGI\ngPtLXcwy7IViQyU0AlYnAZG0O3AqP26x6JyIAX2f1PnbU21gnb8s51iruF9G/M7E\nGwM8CetJMVxpRrPgRwIDAQABo4IBFzCCARMwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\nHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFDqahQcQZyi27/a9BUFuIMGU2g/eMB8GA1Ud\nIwQYMBaAFNLEsNKR1EwRcbNhyz2h/t2oatTjMDQGCCsGAQUFBwEBBCgwJjAkBggr\nBgEFBQcwAYYYaHR0cDovL29jc3AuZ29kYWRkeS5jb20vMDIGA1UdHwQrMCkwJ6Al\noCOGIWh0dHA6Ly9jcmwuZ29kYWRkeS5jb20vZ2Ryb290LmNybDBGBgNVHSAEPzA9\nMDsGBFUdIAAwMzAxBggrBgEFBQcCARYlaHR0cHM6Ly9jZXJ0cy5nb2RhZGR5LmNv\nbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAWQtTvZKGEacke+1bMc8d\nH2xwxbhuvk679r6XUOEwf7ooXGKUwuN+M/f7QnaF25UcjCJYdQkMiGVnOQoWCcWg\nOJekxSOTP7QYpgEGRJHjp2kntFolfzq3Ms3dhP8qOCkzpN1nsoX+oYggHFCJyNwq\n9kIDN0zmiN/VryTyscPfzLXs4Jlet0lUIDyUGAzHHFIYSaRt4bNYC8nY7NmuHDKO\nKHAN4v6mF56ED71XcLNa6R+ghlO773z/aQvgSMO3kwvIClTErF0UZzdsyqUvMQg3\nqm5vjLyb4lddJIGvl5echK1srDdMZvNhkREg5L4wn3qkKQmw4TRfZHcYQFHfjDCm\nrw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIEADCCAuigAwIBAgIBADANBgkqhkiG9w0BAQUFADBjMQswCQYDVQQGEwJVUzEh\nMB8GA1UEChMYVGhlIEdvIERhZGR5IEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBE\nYWRkeSBDbGFzcyAyIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTA0MDYyOTE3\nMDYyMFoXDTM0MDYyOTE3MDYyMFowYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRo\nZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3Mg\nMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASAwDQYJKoZIhvcNAQEBBQADggEN\nADCCAQgCggEBAN6d1+pXGEmhW+vXX0iG6r7d/+TvZxz0ZWizV3GgXne77ZtJ6XCA\nPVYYYwhv2vLM0D9/AlQiVBDYsoHUwHU9S3/Hd8M+eKsaA7Ugay9qK7HFiH7Eux6w\nwdhFJ2+qN1j3hybX2C32qRe3H3I2TqYXP2WYktsqbl2i/ojgC95/5Y0V4evLOtXi\nEqITLdiOr18SPaAIBQi2XKVlOARFmR6jYGB0xUGlcmIbYsUfb18aQr4CUWWoriMY\navx4A6lNf4DD+qta/KFApMoZFv6yyO9ecw3ud72a9nmYvLEHZ6IVDd2gWMZEewo+\nYihfukEHU1jPEX44dMX4/7VpkI+EdOqXG68CAQOjgcAwgb0wHQYDVR0OBBYEFNLE\nsNKR1EwRcbNhyz2h/t2oatTjMIGNBgNVHSMEgYUwgYKAFNLEsNKR1EwRcbNhyz2h\n/t2oatTjoWekZTBjMQswCQYDVQQGEwJVUzEhMB8GA1UEChMYVGhlIEdvIERhZGR5\nIEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBEYWRkeSBDbGFzcyAyIENlcnRpZmlj\nYXRpb24gQXV0aG9yaXR5ggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQAD\nggEBADJL87LKPpH8EsahB4yOd6AzBhRckB4Y9wimPQoZ+YeAEW5p5JYXMP80kWNy\nOO7MHAGjHZQopDH2esRU1/blMVgDoszOYtuURXO1v0XJJLXVggKtI3lpjbi2Tc7P\nTMozI+gciKqdi0FuFskg5YmezTvacPd+mSYgFFQlq25zheabIZ0KbIIOqPjCDPoQ\nHmyW74cNxA9hi63ugyuV+I6ShHI56yDqg+2DzZduCLzrTia2cyvk0/ZM/iZx4mER\ndEr/VxqHD3VILs9RaRegAhJhldXRQLIQTO7ErBBDpqWeCtWVYpoNz4iCxTIM5Cuf\nReYNnyicsbkqWletNw+vHX/bvZ8=\n-----END CERTIFICATE-----\n";
    }

    fn get_default_tlskey() -> &'static str {
        return "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD8akqZ8rNBgcgY\n5GAtQrU92IjUyIXg4LE0T+lbtrAXXOwiXOMvkjxxvDP97RTi4cf9IwGbmkx6CoQH\neGOub9z0fNNWJLmiS5NtCQRRrURNleHH5lU48nVevyxDGjG/V8BlCZ51wWRQmW+5\nxJYKDdmMyus0JGyv0Gw8zBQqhtVakaW6RvyB3zRPDF4IHRR4gcoN3m484nYWevMO\n60PC7OYK/caYpHakh23sONEkjAHAGnt/fDYDemUbwRj521FA6PdeAyoS5tZD6hbZ\nhdIkxXQIe5huwTtZtdiFI0wfKX1rF4VZwDte9DpfXImcLCOIaWTkXttDlyB1oGXc\ntrYXs+fzAgMBAAECggEAC6Kmr7QFWVavL56PZGa3zhMGM7DOoxAYew3X9vdT5K/O\n3sKjYlT+XkvLpb/g/5hizKNpdo/FSLblYSbGiYr0h3ydjVICEJ4lPJh2z4EKLf1j\nvAA9G3PpvyVW1/0EIArefonT+R+iDSkVgl2ygOIkjh3oe63WKMCVzLOnllJC0Xrf\n1iZqQ55Lq203/sRFafFHWFLkM8E/e4yI1NTOaA8sZIx0PYBvYK20jNXhMFGTtNNO\nJqhZydxwVTrXFeg66nf//b+hKDtlkYcvGD0l28njshU+GTZVEyvVtm8fdhQ5akxm\nyKxu31LMsjuQkKGGsDqzPwYdrPhdyqA37M3QlYUn+QKBgQD/97jTFnOAWmPyhqED\nqTWBQUKhOQh7TkMuJxWEx1BmbCAoLh0iymQM5DZbD06hVX7f3PzskiCSN7du0o72\npxoqWkUa27lLpvwuVlMsI3DB2g/Lr+Jer00ssZemRqg6t/xki4q/bxirWGGqsBVZ\nkjpaYssmScHXT1wsTTumIpp+VwKBgQD8cnRdneDfyjZooDkFWgst+GYzU43HMUtP\n2TSihYTnBvCIpEOhYTT8UG0P9EuyEmRxsQeuQ/7hlDKm9G1q5XznIsoZvCxJiffw\nhufmPl13zDZl6tBui6flrlvHTQydwEGX2+se6bMNHi05PRfHWv3Z+TMLO+1JkucM\nehBBwZlpxQKBgGyiD/jWYHKq6hw18wQAvkp7DfIqqGTclDp0L/fIN2Egpo0m9Qqc\n5tVpzX/cAT0LcetEeLtWUSh9KQaJqk8YIEy1PvrlIcDvv7tSu73R1LsQ9v81SFdz\nAsfjHz9cYW16RE3PwzT3y3p86gZs8MKxAr71is5XI0Nj1PSgWp5ptTPFAoGADktw\n2Wg6NpHduNjxwaLSpTy+lMNzcMcSy6ex+k3zM53J+wLKLZYyiOMI+fFMY/30oBd1\nJuIEycM5hwiqNXZfNztaFFD6dQOR/ZW2BeycIE94+RZtzQStci0IV2W+hCRB0paK\nXsq+78w4pVgXQ5ucaj5ZLJatHhBqcuNqjj6nMD0CgYEApzLZLwKzQnyhfg1qEMCX\niyusED9kUvK9qCNL/5pStr2FsyJ+mqp1mLZiV0E4+ytLbnnZXX3IyLyYe9YqHExn\n6Jhv467r2sx0WNu678DqWLzlXowA3vylE/AL+Oi7qvG8UceQnWdJ5fWdir+9SyKF\nNqMnuY68MWZAszGai3MRsPE=\n-----END PRIVATE KEY-----\n";
    }

    #[tokio::test]
    async fn test_build() {
        let builder = TlsServerBuilder::new(get_default_tlscert(), get_default_tlskey()).unwrap();
        let server = builder.build().unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:8443")
            .await
            .unwrap();
        loop {
            let (stream, addr) = listener.accept().await.unwrap();
            println!("{:?}", addr);
            let mut tls_stream = server.accept(stream).await.unwrap();
            tls_stream.write_all(b"hello world").await.unwrap();
            break;
        }
    }
}
