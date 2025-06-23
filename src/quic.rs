use ::aead::KeySizeUser;
use alloc::boxed::Box;
use rustls::Error;
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::quic::{Algorithm, HeaderProtectionKey, PacketKey, Tag};

const TAG_LEN: usize = 16;

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

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        Box::new(QuicHeaderKey {
            algorithm: *self,
            key,
        })
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
        if payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let plain_len = payload.len() - TAG_LEN;
        match self.algorithm {
            QuicAlgorithm::ChaCha => {
                use chacha20poly1305::Tag as CTag;
                use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
                let c = ChaCha20Poly1305::new(self.key.as_ref().into());
                let tag = Tag::from(&payload[plain_len..plain_len + 16]);
                let ctag = CTag::from_slice(tag.as_ref());
                c.decrypt_in_place_detached(
                    &(nonce.0.into()),
                    header_aad,
                    &mut payload[..plain_len],
                    ctag,
                )
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
        TAG_LEN // for all three algorithms
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

pub struct QuicHeaderKey {
    algorithm: QuicAlgorithm,
    key: AeadKey,
}

impl HeaderProtectionKey for QuicHeaderKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, true)
    }

    #[inline]
    fn sample_len(&self) -> usize {
        TAG_LEN
    }
}

impl QuicHeaderKey {
    /// Generate a new QUIC Header Protection mask.
    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], Error> {
        let mut out: [u8; 5] = [0; 5];
        match self.algorithm {
            QuicAlgorithm::ChaCha => {
                // https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.4
                use chacha20::ChaCha20;
                use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
                let block_counter = u32::from_le_bytes(sample[..4].try_into().unwrap());
                let nonce: [u8; 12] = sample[4..16].try_into().unwrap();
                let key: [u8; 32] = self.key.as_ref().try_into().unwrap();
                let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
                cipher.seek(block_counter as u64 * 64); // block size is 64
                cipher.apply_keystream(out.as_mut_slice());
            }
            QuicAlgorithm::Aes128 => {
                // Just do AES-ECB and take the first 5 bytes
                todo!()
                //aes_gcm::aes::
                //let mut out: [u8; 5] = [0; 5];
            }
            QuicAlgorithm::Aes256 => {
                // Just do AES-ECB and take the first 5 bytes
                todo!()
                //aes_gcm::aes::
                //let mut out: [u8; 5] = [0; 5];
                //out.copy_from_slice(&block.as_ref()[..5]);
                //out
            }
        }
        Ok(out)
    }

    fn xor_in_place(
        &self,
        sample: &[u8], // 16 bytes long
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), Error> {
        // This implements "Header Protection Application" almost verbatim.
        // <https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1>

        let mask = self
            .new_mask(sample)
            .map_err(|_| Error::General("sample of invalid length".into()))?;

        // The `unwrap()` will not panic because `new_mask` returns a
        // non-empty result.
        let (first_mask, pn_mask) = mask.split_first().unwrap();

        // It is OK for the `mask` to be longer than `packet_number`,
        // but a valid `packet_number` will never be longer than `mask`.
        if packet_number.len() > pn_mask.len() {
            return Err(Error::General("packet number too long".into()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls13::*;

    // See https://datatracker.ietf.org/doc/html/rfc9001#name-sample-packet-protection

    #[test]
    fn test_rfc9001_a5() {
        // https://datatracker.ietf.org/doc/html/rfc9001#name-chacha20-poly1305-short-hea
        // let secret_bytes = hex::decode("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b").unwrap();

        let rfc_key =
            hex::decode("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
                .unwrap();
        let rfc_iv = hex::decode("e0459b3474bdd0e44a41c144").unwrap();
        let rfc_hp =
            hex::decode("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
                .unwrap();
        let rfc_pn: u64 = 654360564; // 0x2700bff4
        let rfc_nonce = hex::decode("e0459b3474bdd0e46d417eb0").unwrap();
        let rfc_unprotected_header = hex::decode("4200bff4").unwrap();
        let rfc_payload = hex::decode("01").unwrap();
        let rfc_payload_ciphertext = hex::decode("655e5cd55c41f69080575d7999c25a5bfb").unwrap();
        let rfc_sample = hex::decode("5e5cd55c41f69080575d7999c25a5bfb").unwrap();
        let rfc_mask = hex::decode("aefefe7d03").unwrap();
        let rfc_header = hex::decode("4cfe4189").unwrap();
        let rfc_packet = hex::decode("4cfe4189655e5cd55c41f69080575d7999c25a5bfb").unwrap();
        let rfc_packet_header = &rfc_packet[0..4];
        let rfc_packet_encrypted = &rfc_packet[4..5];
        let rfc_packet_tag = &rfc_packet[5..];

        use rustls::crypto::cipher::{AeadKey, Iv};

        // Get a packet key
        let packet_key = {
            let aead_key: AeadKey = TryInto::<[u8; 32]>::try_into(rfc_key.as_slice())
                .unwrap()
                .into();
            let iv: Iv = TryInto::<[u8; 12]>::try_into(rfc_iv.as_slice())
                .unwrap()
                .into();
            QuicAlgorithm::ChaCha.packet_key(aead_key, iv)
        };

        // Copy payload into mutable
        let mut payload = rfc_payload.clone();

        // Encrypt the packet
        let tag = packet_key
            .encrypt_in_place(rfc_pn, &*rfc_unprotected_header, &mut payload)
            .unwrap();

        // Test packet encryption
        assert_eq!(payload, rfc_packet_encrypted);
        assert_eq!(tag.as_ref(), rfc_packet_tag);

        // Get a header protection key
        let header_protection_key = {
            let aead_key: AeadKey = TryInto::<[u8; 32]>::try_into(rfc_hp.as_slice())
                .unwrap()
                .into();
            QuicAlgorithm::ChaCha.header_protection_key(aead_key)
        };

        let pn_length = ((rfc_unprotected_header[0] & 0x03) + 1) as usize;
        assert_eq!(pn_length, 3);

        // Copy unprotected header into mutable parts
        let mut first = rfc_unprotected_header[0];
        let mut packet_number_field = rfc_unprotected_header[1..1 + pn_length].to_vec();

        // Protect the header
        header_protection_key
            .encrypt_in_place(
                rfc_sample.as_slice(),
                &mut first,
                &mut packet_number_field[..],
            )
            .unwrap();

        // Test header protection
        assert_eq!(first, rfc_header[0]);
        assert_eq!(packet_number_field.as_slice(), &rfc_header[1..4]);

        // Unprotect the header
        header_protection_key
            .decrypt_in_place(
                rfc_sample.as_slice(),
                &mut first,
                &mut packet_number_field[..],
            )
            .unwrap();

        // Test header protection decryption
        assert_eq!(first, rfc_unprotected_header[0]);
        assert_eq!(
            packet_number_field.as_slice(),
            &rfc_unprotected_header[1..4]
        );

        // Package encrypted payload for in place decryption
        let mut payload = rfc_packet[4..].to_vec();
        assert_eq!(payload.len(), 17);

        // Decrypt packet
        packet_key
            .decrypt_in_place(rfc_pn, &*rfc_unprotected_header, &mut payload)
            .unwrap();

        // Test packet decryption
        assert_eq!(&payload[0..1], rfc_payload);
    }
}
