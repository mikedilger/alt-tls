use ::aead::KeySizeUser;
use alloc::boxed::Box;
use rustls::Error;
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::quic::{Algorithm, HeaderProtectionKey, PacketKey, Tag};

pub enum QuicAlgorithm {
    ChaCha,
    Aes128,
    Aes256,
}

impl Algorithm for QuicAlgorithm {
    fn packet_key(&self, _key: AeadKey, _iv: Iv) -> Box<dyn PacketKey> {
        todo!()
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
        _header_aad: &[u8],
        _payload: &mut [u8],
    ) -> Result<Tag, Error> {
        let _nonce = Nonce::new(&self.iv, packet_number);
        match self.algorithm {
            QuicAlgorithm::ChaCha => {
                todo!()
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
        _header_aad: &[u8],
        _payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let _nonce = Nonce::new(&self.iv, packet_number);
        match self.algorithm {
            QuicAlgorithm::ChaCha => {
                todo!()
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
