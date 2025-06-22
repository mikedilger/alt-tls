use ::aead::KeySizeUser;
use alloc::boxed::Box;
use rustls::crypto::cipher::{AeadKey, Iv};
use rustls::quic::{Algorithm, HeaderProtectionKey, PacketKey};

pub struct Chacha;

pub struct Aes128;

pub struct Aes256;

impl Algorithm for Chacha {
    fn packet_key(&self, _key: AeadKey, _iv: Iv) -> Box<dyn PacketKey> {
        todo!()
    }

    fn header_protection_key(&self, _key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        todo!()
    }

    fn aead_key_len(&self) -> usize {
        chacha20poly1305::ChaCha20Poly1305::key_size()
    }
}

impl Algorithm for Aes128 {
    fn packet_key(&self, _key: AeadKey, _iv: Iv) -> Box<dyn PacketKey> {
        todo!()
    }

    fn header_protection_key(&self, _key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        todo!()
    }

    fn aead_key_len(&self) -> usize {
        aes_gcm::Aes128Gcm::key_size()
    }
}

impl Algorithm for Aes256 {
    fn packet_key(&self, _key: AeadKey, _iv: Iv) -> Box<dyn PacketKey> {
        todo!()
    }

    fn header_protection_key(&self, _key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        todo!()
    }

    fn aead_key_len(&self) -> usize {
        aes_gcm::Aes256Gcm::key_size()
    }
}
