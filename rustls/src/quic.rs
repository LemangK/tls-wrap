use bytes::Bytes;
use rustls::quic;
use std::io;
pub use tls_wrap_common::quic::{Keys, Version, HeaderKey as IHeaderKey, PacketKey as IPacketKey};

pub fn quic_client_keys_initial(
    version: &Version,
    dst_conn_id: &[u8],
) -> io::Result<Keys<HeaderKey, PacketKey>> {
    let v = match version {
        Version::V1Draft => quic::Version::V1Draft,
        Version::V1 => quic::Version::V1,
        Version::V2 => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "quic: rustls unsupported version 2",
            ));
        }
    };
    let keys = quic::Keys::initial(v, dst_conn_id, true);
    Ok(Keys {
        header: HeaderKey {
            inner: keys.local.header,
        },
        packet: PacketKey {
            inner: keys.local.packet,
        },
    })
}

pub struct HeaderKey {
    inner: quic::HeaderProtectionKey,
}

impl tls_wrap_common::quic::HeaderKey for HeaderKey {
    fn sample_len(&self) -> usize {
        self.inner.sample_len()
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> io::Result<()> {
        let ret = self
            .inner
            .decrypt_in_place(sample, first, packet_number)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(ret)
    }
}

pub struct PacketKey {
    inner: quic::PacketKey,
}

impl tls_wrap_common::quic::PacketKey for PacketKey {
    fn decrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> io::Result<Bytes> {
        let ret = self
            .inner
            .decrypt_in_place(packet_number, header, payload)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(Bytes::copy_from_slice(ret))
    }
}
