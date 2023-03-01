/// BoringSSL
/// support:
/// * iOS[ALL]: aarch64, x86_64
/// * macOS[ALL]: aarch64, x86_64
/// * android[ALL]: armv8, armv7a, x86, x86_64
/// * windows: x86_64
/// * linux: x86_64
macro_rules! cfg_boringssl {
    ($($item:item)*) => {
        $(
            #[cfg(any(
                target_os = "ios",
                target_os = "macos",
                target_os = "android",
                all(target_os = "windows", target_arch = "x86_64"),
                all(target_os = "linux", target_arch = "x86_64"),
            ))]
            $item
        )*
    };
}

/// Openssl
/// support:
/// * linux: mips, mips64
macro_rules! cfg_openssl {
    ($($item:item)*) => {
        $(
            #[cfg(all(target_os = "linux", any(target_arch = "mips", target_arch = "mips64")))]
            $item
        )*
    };
}

/// Rustls--Fallback
/// support:
/// * windows: x86, aarch64
/// * linux: x86, aarch64, armv7
macro_rules! cfg_rustls {
    ($($item:item)*) => {
        $(
            #[cfg(any(
                all(target_os = "linux", target_arch = "x86"),
                all(target_os = "linux", target_arch = "aarch64"),
                all(target_os = "linux", target_arch = "arm"),
                all(target_os = "windows", target_arch = "aarch64"),
                all(target_os = "windows", target_arch = "x86"),
            ))]
            $item
        )*
    };
}

pub use tls_wrap_common::{ClientBuilder, is_path};

cfg_boringssl! {
    pub use tls_wrap_boring::*;
}

cfg_openssl! {
    pub use tls_wrap_openssl::*;
}

cfg_rustls! {
    pub use tls_wrap_rustls::*;
}
