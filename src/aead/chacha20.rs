use super::{DecryptBufferAdapter, EncryptBufferAdapter};
use alloc::boxed::Box;
use chacha20poly1305::{AeadInPlace, KeyInit, KeySizeUser};
use rustls::crypto::cipher::{
    self, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

pub struct Chacha20Poly1305;

impl Tls13AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("key should be valid"),
            iv,
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("key should be valid"),
            iv,
        ))
    }

    fn key_len(&self) -> usize {
        chacha20poly1305::ChaCha20Poly1305::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

struct Tls13Cipher(chacha20poly1305::ChaCha20Poly1305, Iv);

impl MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());

        let nonce: chacha20poly1305::Nonce = cipher::Nonce::new(&self.1, seq).0.into();
        let aad = cipher::make_tls13_aad(total_len);

        self.0
            .encrypt_in_place(&nonce, &aad, &mut EncryptBufferAdapter(&mut payload))
            .map_err(|_| rustls::Error::EncryptError)
            .map(|()| {
                OutboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    payload,
                )
            })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for Tls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        let nonce: chacha20poly1305::Nonce = cipher::Nonce::new(&self.1, seq).0.into();
        let aad = cipher::make_tls13_aad(payload.len());

        self.0
            .decrypt_in_place(&nonce, &aad, &mut DecryptBufferAdapter(payload))
            .map_err(|_| rustls::Error::DecryptError)?;

        m.into_tls13_unpadded_message()
    }
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;
