use super::{new_error, X509};
use std::io;
use std::path::Path;

pub fn load_native_certs() -> io::Result<Vec<X509>> {
    let mut store = Vec::new();
    let (files, directories) = get_cert();

    let mut first_error: Option<io::Error> = None;
    let mut bytes = Vec::new();

    match std::env::var(CERT_FILE_ENV) {
        Ok(path) if !path.is_empty() => {
            read_files(
                [path].iter(),
                &mut bytes,
                &mut store,
                &mut first_error,
                true,
            );
        }
        _ => {
            read_files(files.iter(), &mut bytes, &mut store, &mut first_error, true);
        }
    }

    match std::env::var(CERT_DIR_ENV) {
        Ok(path) if !path.is_empty() => {
            // OpenSSL and BoringSSL both use ":" as the SSL_CERT_DIR separator.
            // See:
            //  * https://golang.org/issue/35325
            //  * https://www.openssl.org/docs/man1.0.2/man1/c_rehash.html
            read_dirs(
                path.split(":").into_iter(),
                &mut bytes,
                &mut store,
                &mut first_error,
            );
        }
        _ => {
            read_dirs(
                directories.into_iter(),
                &mut bytes,
                &mut store,
                &mut first_error,
            );
        }
    }

    match (first_error, store.is_empty()) {
        (Some(err), true) => Err(err),
        _ => Ok(store),
    }
}

// CERT_FILE_ENV is the environment variable which identifies where to locate
// the SSL certificate file. If set this overrides the system default.
const CERT_FILE_ENV: &'static str = "SSL_CERT_FILE";

// CERT_DIR_ENV is the environment variable which identifies which directory
// to check for SSL certificate files. If set this overrides the system default.
// It is a colon separated list of directories.
// See https://www.openssl.org/docs/man1.0.2/man1/c_rehash.html.
const CERT_DIR_ENV: &'static str = "SSL_CERT_DIR";

fn read_files<I>(
    iter: I,
    bytes: &mut Vec<u8>,
    store: &mut Vec<X509>,
    first_error: &mut Option<io::Error>,
    stop: bool,
) where
    I: Iterator,
    I::Item: AsRef<str>,
{
    for path in iter {
        match read(path.as_ref(), bytes) {
            Ok(n) => {
                if let Ok(certs) = X509::stack_from_pem(&bytes[..n]).map_err(new_error) {
                    store.extend(certs);
                    if stop {
                        break;
                    }
                }
            }
            Err(e) if e.kind() != io::ErrorKind::NotFound && first_error.is_none() => {
                *first_error = Some(e);
            }
            _ => {}
        }
    }
}

fn read_dirs<I>(
    iter: I,
    bytes: &mut Vec<u8>,
    store: &mut Vec<X509>,
    first_error: &mut Option<io::Error>,
) where
    I: Iterator,
    I::Item: AsRef<str>,
{
    for dir in iter {
        match read_unique_directory_entries(Path::new(dir.as_ref())) {
            Ok(paths) => read_files(paths.into_iter(), bytes, store, &mut None, false),
            Err(err) if err.kind() == io::ErrorKind::NotFound && first_error.is_none() => {
                *first_error = Some(err);
            }
            _ => {}
        }
    }
}

pub fn read<P: AsRef<Path>>(path: P, bytes: &mut Vec<u8>) -> io::Result<usize> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    bytes.clear();
    file.read_to_end(bytes)
}

fn is_same_dir_symlink(f: &std::fs::DirEntry, dir: &Path) -> bool {
    if let Ok(typ) = f.file_type() {
        if !typ.is_symlink() {
            return false;
        }
    }
    match std::fs::read_link(dir.join(f.file_name())) {
        Ok(target) => target.to_string_lossy().contains("/"),
        Err(_) => false,
    }
}

fn read_unique_directory_entries<P: AsRef<Path>>(path: P) -> io::Result<Vec<String>> {
    let p = path.as_ref();
    let mut res = Vec::new();
    for item in std::fs::read_dir(p)? {
        if let Ok(d) = item {
            if !is_same_dir_symlink(&d, p) {
                res.push(format!(
                    "{}/{}",
                    p.to_string_lossy(),
                    d.file_name().to_string_lossy()
                ));
            }
        }
    }
    Ok(res)
}

fn get_cert() -> (Vec<&'static str>, Vec<&'static str>) {
    let mut cert_files = Vec::new();
    let mut cert_directories = Vec::new();
    // FreeBsd
    #[cfg(target_os = "freebsd")]
    {
        cert_files.push("/usr/local/etc/ssl/cert.pem");

        cert_directories.push("/etc/ssl/certs"); // FreeBSD 12.2+
        cert_directories.push("/usr/local/share/certs");
    }

    // OpenBsd
    #[cfg(target_os = "openbsd")]
    cert_files.push("/etc/ssl/cert.pem");

    // Dragonfly
    #[cfg(target_os = "dragonfly")]
    cert_files.push("/usr/local/share/certs/ca-root-nss.crt");

    // NetBsd
    #[cfg(target_os = "netbsd")]
    {
        cert_files.push("/etc/openssl/certs/ca-certificates.crt");

        cert_directories.push("/etc/openssl/certs");
    }

    // Linux
    #[cfg(target_os = "linux")]
    {
        cert_files.push("/etc/ssl/certs/ca-certificates.crt"); // Debian/Ubuntu/Gentoo etc.
        cert_files.push("/etc/pki/tls/certs/ca-bundle.crt"); // Fedora/RHEL 6
        cert_files.push("/etc/ssl/ca-bundle.pem"); // OpenSUSE
        cert_files.push("/etc/pki/tls/cacert.pem"); // OpenELEC
        cert_files.push("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"); // CentOS/RHEL 7
        cert_files.push("/etc/ssl/cert.pem"); // Alpine Linux

        cert_directories.push("/etc/ssl/certs"); // SLES10/SLES11, https://golang.org/issue/12139
        cert_directories.push("/etc/pki/tls/certs"); // Fedora/RHEL
    }

    // Android
    #[cfg(target_os = "android")]
    {
        cert_directories.push("/system/etc/security/cacerts");
    }

    // Solaris
    #[cfg(target_os = "solaris")]
    {
        cert_files.push("/etc/certs/ca-certificates.crt"); // Solaris 11.2+
        cert_files.push("/etc/ssl/certs/ca-certificates.crt"); // Joyent SmartOS
        cert_files.push("/etc/ssl/cacert.pem"); // OmniOS

        cert_directories.push("/etc/certs/CA");
    }

    // AIX
    cert_files.push("/var/ssl/certs/ca-bundle.crt");
    cert_directories.push("/var/ssl/certs");

    // PLAN9
    cert_files.push("/sys/lib/tls/ca.pem");

    (cert_files, cert_directories)
}
