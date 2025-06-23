use ::aead::KeySizeUser;
use alloc::boxed::Box;
use rustls::Error;
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::quic::{Algorithm, HeaderProtectionKey, PacketKey, Tag};

#[derive(Clone, Copy)]
pub enum QuicAlgorithm {
    ChaCha,
    Aes128,
    Aes256,
}

impl Algorithm for QuicAlgorithm {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn PacketKey> {
        Box::new(QuicPacketKey {
            algorithm: *self,
            key,
            iv,
        })
    }

    fn header_protection_key(&self, _key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        todo!()
    }

    fn aead_key_len(&self) -> usize {
        match &self {
            QuicAlgorithm::ChaCha => 16,
            QuicAlgorithm::Aes128 => aes_gcm::Aes128Gcm::key_size(),
            QuicAlgorithm::Aes256 => aes_gcm::Aes256Gcm::key_size(),
        }
    }
}

pub struct QuicPacketKey {
    algorithm: QuicAlgorithm,
    key: AeadKey,
    iv: Iv,
}

impl PacketKey for QuicPacketKey {
    /// Encrypt a QUIC packet
    ///
    /// Takes a packet_number, used to derive the nonce; the packet header, which is used as the additional authenticated data; and the payload. The authentication tag is returned if encryption succeeds.
    ///
    /// Fails if and only if the payload is longer than allowed by the cipher suite’s AEAD algorithm.
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header_aad: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {
        let nonce = Nonce::new(&self.iv, packet_number);
        match self.algorithm {
            QuicAlgorithm::ChaCha => {
                use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
                let c = ChaCha20Poly1305::new(self.key.as_ref().into());
                let ctag = c
                    .encrypt_in_place_detached(&(nonce.0.into()), header_aad, payload)
                    .map_err(|_| Error::EncryptError)?;
                Ok(Tag::from(ctag.as_slice()))
            }
            QuicAlgorithm::Aes128 => {
                todo!()
            }
            QuicAlgorithm::Aes256 => {
                todo!()
            }
        }
    }

    /// Decrypt a QUIC packet
    ///
    /// Takes the packet header, which is used as the additional authenticated data, and the payload, which includes the authentication tag.
    ///
    /// If the return value is Ok, the decrypted payload can be found in payload, up to the length found in the return value.
    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header_aad: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let nonce = Nonce::new(&self.iv, packet_number);
        let plain_len = payload.len() - self.tag_len();
        match self.algorithm {
            QuicAlgorithm::ChaCha => {
                use chacha20poly1305::Tag as CTag;
                use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
                let c = ChaCha20Poly1305::new(self.key.as_ref().into());
                let tag = Tag::from(&payload[plain_len..plain_len + 16]);
                let ctag = CTag::from_slice(tag.as_ref());
                c.decrypt_in_place_detached(&(nonce.0.into()), header_aad, payload, ctag)
                    .map_err(|_| Error::DecryptError)?;
                Ok(&payload[..plain_len])
            }
            QuicAlgorithm::Aes128 => {
                todo!()
            }
            QuicAlgorithm::Aes256 => {
                todo!()
            }
        }
    }

    fn tag_len(&self) -> usize {
        16 // for all three algorithms
    }

    // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
    fn confidentiality_limit(&self) -> u64 {
        match self.algorithm {
            QuicAlgorithm::ChaCha => u64::MAX,
            QuicAlgorithm::Aes128 => 1 << 23,
            QuicAlgorithm::Aes256 => 1 << 23,
        }
    }

    // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
    fn integrity_limit(&self) -> u64 {
        match self.algorithm {
            QuicAlgorithm::ChaCha => 1 << 36,
            QuicAlgorithm::Aes128 => 1 << 52,
            QuicAlgorithm::Aes256 => 1 << 52,
        }
    }
}
