use std::io;

pub trait Hkdf {
    fn extract(&self, key: &[u8], salt: &[u8], out: &mut [u8]) -> io::Result<usize>;
    fn expand(&self, prk: &[u8], info: &[u8], buf: &mut [u8]) -> io::Result<()>;
}

pub trait Cipher {
    fn block_size(&self) -> usize;
    fn encrypt(&self, key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> io::Result<Vec<u8>>;
}

pub trait AeadCipher {
    fn decrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        aad: &[u8],
        data: &[u8],
        tag: &[u8],
    ) -> io::Result<Vec<u8>>;
}

// Golang /crypto/aes/aes_gcm.go
pub struct AeadAesGcmTls13 {
    key: [u8; 16],
    nonce_mask: [u8; 12],
    cipher: Box<dyn AeadCipher>,
    nonce_size: usize,
    tag_size: usize,
}

impl AeadAesGcmTls13 {
    pub fn new(cipher: Box<dyn AeadCipher>, key: [u8; 16], nonce_mask: [u8; 12]) -> Self {
        Self {
            key,
            nonce_mask,
            cipher,
            nonce_size: 12,
            tag_size: 16,
        }
    }

    // 64-bit sequence number
    pub fn nonce_size(&self) -> usize {
        8
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        if self.nonce_mask.len() != self.nonce_size {
            panic!("incorrect nonce length given to GCM");
        }

        let mut nonce_mask = [0u8; 12];
        nonce_mask.copy_from_slice(&self.nonce_mask);

        for (i, b) in nonce.iter().enumerate() {
            nonce_mask[4 + i] ^= b
        }

        const MINIMUM_TAG_SIZE: usize = 12;
        if self.tag_size < MINIMUM_TAG_SIZE {
            panic!("incorrect GCM tag size")
        }

        // The AES block size in bytes.
        const BLOCK_SIZE: usize = 16;
        if ciphertext.len() < self.tag_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "message authentication failed",
            ));
        }
        if ciphertext.len() as u64
            > ((1u64 << 32) - 2) * (BLOCK_SIZE as u64) + (self.tag_size as u64)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "message authentication failed",
            ));
        }

        let tag = &ciphertext[ciphertext.len() - self.tag_size..];
        let data = &ciphertext[..ciphertext.len() - self.tag_size];
        self.cipher
            .decrypt(&self.key[..], Some(&nonce_mask[..]), aad, data, tag)
    }
}

pub mod impls {
    use super::*;
    use crate::quic::{Keys, Version};
    use bytes::{BufMut, Bytes};

    pub fn quic_client_keys_initial(
        version: &Version,
        dst_conn_id: &[u8],
        hkdf: Box<dyn Hkdf>,
        cipher: Box<dyn Cipher>,
        aead_cipher: Box<dyn AeadCipher>,
    ) -> io::Result<Keys<HeaderKey, PacketKey>> {
        const CLIENT_LABEL: &[u8] = b"client in";
        const SHA256_SIZE: usize = 32; // MessageDigest::sha256().size()

        let mut prk = [0u8; SHA256_SIZE];
        let prk_len =
            hkdf.extract(dst_conn_id, version.initial_salt(), &mut prk)?;

        let mut client_secret = [0u8; SHA256_SIZE];
        hkdf_expand_label(
            hkdf.as_ref(),
            &prk[..prk_len],
            &[],
            CLIENT_LABEL,
            &mut client_secret,
        )?;
        let (key, iv) = compute_initial_key_and_iv(hkdf.as_ref(), &client_secret, &version)?;
        Ok(Keys {
            header: HeaderKey::new(hkdf, cipher, client_secret),
            packet: PacketKey::new(aead_cipher, key, iv),
        })
    }

    pub struct PacketKey {
        aes_gcm_tls13: AeadAesGcmTls13,
    }

    impl PacketKey {
        pub fn new(cipher: Box<dyn AeadCipher>, key: [u8; 16], nonce_mask: [u8; 12]) -> Self {
            Self {
                aes_gcm_tls13: AeadAesGcmTls13::new(cipher, key, nonce_mask),
            }
        }
    }

    impl crate::quic::PacketKey for PacketKey {
        fn decrypt_in_place(
            &self,
            packet_number: u64,
            header: &[u8],
            payload: &mut [u8],
        ) -> io::Result<Bytes> {
            let mut nonce = vec![0u8; self.aes_gcm_tls13.nonce_size()];
            {
                let l = nonce.len();
                (&mut nonce[l - 8..]).put_u64(packet_number);
            }
            let ret = self.aes_gcm_tls13.decrypt(&nonce, payload, header)?;
            return Ok(Bytes::from(ret));
        }
    }

    pub struct HeaderKey {
        secret: [u8; 32],
        hkdf: Box<dyn Hkdf>,
        cipher: Box<dyn Cipher>,
    }

    impl HeaderKey {
        pub fn new(hkdf: Box<dyn Hkdf>, cipher: Box<dyn Cipher>, secret: [u8; 32]) -> Self {
            Self { hkdf, cipher, secret }
        }
    }

    impl crate::quic::HeaderKey for HeaderKey {
        fn sample_len(&self) -> usize {
            16
        }

        /// rustls/src/quic.rs xor_in_place
        fn decrypt_in_place(
            &self,
            sample: &[u8],
            first: &mut u8,
            packet_number: &mut [u8],
        ) -> io::Result<()> {
            let masked: bool = true;
            let mut key = [0u8; 16];
            {
                hkdf_expand_label(self.hkdf.as_ref(), &self.secret, &[], b"quic hp", &mut key)?;
            }

            let raw_mask = self.cipher.encrypt(&key, None, sample)?;
            let mask = &raw_mask[..self.cipher.block_size()];

            // The `unwrap()` will not panic because `new_mask` returns a
            // non-empty result.
            let (first_mask, pn_mask) = mask.split_first().unwrap();

            // It is OK for the `mask` to be longer than `packet_number`,
            // but a valid `packet_number` will never be longer than `mask`.
            if packet_number.len() > pn_mask.len() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "packet number too long",
                ));
            }

            // Infallible from this point on. Before this point, `first` and
            // `packet_number` are unchanged.

            const LONG_HEADER_FORM: u8 = 0x80;
            let bits = match *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
                true => 0x0f,  // Long header: 4 bits masked
                false => 0x1f, // Short header: 5 bits masked
            };

            let first_plain = match masked {
                // When unmasking, use the packet length bits after unmasking
                true => *first ^ (first_mask & bits),
                // When masking, use the packet length bits before masking
                false => *first,
            };
            let pn_len = (first_plain & 0x03) as usize + 1;

            *first ^= first_mask & bits;
            for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
                *dst ^= m;
            }

            Ok(())
        }
    }

    fn compute_initial_key_and_iv(
        hkdf: &dyn Hkdf,
        prk: &[u8],
        v: &Version,
    ) -> io::Result<([u8; 16], [u8; 12])> {
        let mut key_label: &[u8] = b"quic key";
        let mut iv_label: &[u8] = b"quic iv";
        if v == &Version::V2 {
            key_label = b"quicv2 key";
            iv_label = b"quicv2 iv";
        }
        let mut key = [0u8; 16];
        hkdf_expand_label(hkdf, prk, &[], key_label, &mut key)?;
        let mut iv = [0u8; 12];
        hkdf_expand_label(hkdf, prk, &[], iv_label, &mut iv)?;
        Ok((key, iv))
    }

    fn hkdf_expand_label(
        hkdf: &dyn Hkdf,
        prk: &[u8],
        context: &[u8],
        label: &[u8],
        out: &mut [u8],
    ) -> io::Result<()> {
        let mut tmp = [0u8; 64];
        const LABEL_TLS13: &[u8] = b"tls13 ";

        let output_len = u16::to_be_bytes(out.len() as u16);
        let label_len = u8::to_be_bytes((LABEL_TLS13.len() + label.len()) as u8);
        let context_len = u8::to_be_bytes(context.len() as u8);

        let info = &[
            &output_len[..],
            &label_len[..],
            LABEL_TLS13,
            label,
            &context_len[..],
            context,
        ];

        // Count
        let mut count: usize = 0;
        info.iter().for_each(|e| count += e.len());
        if count > tmp.len() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "hkdf_expand_label: info.len() > 64",
            ));
        }

        // Fill
        {
            let mut bs = &mut tmp[..];
            info.iter().for_each(|e| bs.put_slice(e));
        }

        if let Err(err) = hkdf.expand(prk, &tmp[..count], out) {
            tracing::warn!("quic: HKDF-Expand-Label invocation failed unexpectedly");
            return Err(err.into());
        }
        Ok(())
    }
}
