use bytes::Bytes;
use std::io;

pub mod openssl_like;

pub struct Keys<H, P>
    where
        H: HeaderKey,
        P: PacketKey,
{
    pub header: H,
    pub packet: P,
}

/// QUIC protocol version
///
/// Governs version-specific behavior in the TLS layer
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    /// Draft versions 29, 30, 31 and 32
    V1Draft,
    /// First stable RFC
    V1,
    V2,
}

impl Version {
    pub fn from_u32(value: u32) -> Option<Version> {
        match value {
            0xff00001d => Some(Version::V1Draft),
            0x1 => Some(Version::V1),
            0x709a50c4 => Some(Version::V2),
            _ => None,
        }
    }

    pub fn to_u32(&self) -> u32 {
        match self {
            Version::V1Draft => 0xff00001d,
            Version::V1 => 0x1,
            Version::V2 => 0x709a50c4,
        }
    }

    pub fn initial_salt(self) -> &'static [u8; 20] {
        match self {
            Self::V1Draft => &[
                // https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-32#section-5.2
                0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61,
                0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
            ],
            Self::V1 => &[
                // https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
            ],
            Self::V2 => &[
                0xa7, 0x07, 0xc2, 0x03, 0xa5, 0x9b, 0x47, 0x18, 0x4a, 0x1d, 0x62, 0xca, 0x57, 0x04,
                0x06, 0xea, 0x7a, 0xe3, 0xe5, 0xd3,
            ],
        }
    }
}

pub trait PacketKey {
    fn decrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> io::Result<Bytes>;
}

pub trait HeaderKey {
    fn sample_len(&self) -> usize;
    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> io::Result<()>;
}
