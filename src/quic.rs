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
            key: match self {
                QuicAlgorithm::ChaCha => InnerKey::Key256(key.as_ref()[..32].try_into().unwrap()),
                QuicAlgorithm::Aes128 => InnerKey::Key128(key.as_ref()[..16].try_into().unwrap()),
                QuicAlgorithm::Aes256 => InnerKey::Key256(key.as_ref()[..32].try_into().unwrap()),
            },
            iv,
        })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        Box::new(QuicHeaderKey {
            algorithm: *self,
            key: match self {
                QuicAlgorithm::ChaCha => InnerKey::Key256(key.as_ref()[..32].try_into().unwrap()),
                QuicAlgorithm::Aes128 => InnerKey::Key128(key.as_ref()[..16].try_into().unwrap()),
                QuicAlgorithm::Aes256 => InnerKey::Key256(key.as_ref()[..32].try_into().unwrap()),
            },
        })
    }

    fn aead_key_len(&self) -> usize {
        match self {
            QuicAlgorithm::ChaCha => 32,
            QuicAlgorithm::Aes128 => aes_gcm::Aes128Gcm::key_size(), // 16
            QuicAlgorithm::Aes256 => aes_gcm::Aes256Gcm::key_size(), // 32
        }
    }
}

pub enum InnerKey {
    Key128([u8; 16]),
    Key256([u8; 32]),
}

impl AsRef<[u8]> for InnerKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            InnerKey::Key128(i) => i.as_slice(),
            InnerKey::Key256(i) => i.as_slice(),
        }
    }
}

pub struct QuicPacketKey {
    algorithm: QuicAlgorithm,
    key: InnerKey,
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
                use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit};
                let c = Aes128Gcm::new(self.key.as_ref().into());
                let ctag = c
                    .encrypt_in_place_detached(&(nonce.0.into()), header_aad, payload)
                    .map_err(|_| Error::EncryptError)?;
                Ok(Tag::from(ctag.as_slice()))
            }
            QuicAlgorithm::Aes256 => {
                use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit};
                let c = Aes256Gcm::new(self.key.as_ref().into());
                let ctag = c
                    .encrypt_in_place_detached(&(nonce.0.into()), header_aad, payload)
                    .map_err(|_| Error::EncryptError)?;
                Ok(Tag::from(ctag.as_slice()))
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
                use aes_gcm::Tag as CTag;
                use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit};
                let c = Aes128Gcm::new(self.key.as_ref().into());
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
            QuicAlgorithm::Aes256 => {
                use aes_gcm::Tag as CTag;
                use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit};
                let c = Aes256Gcm::new(self.key.as_ref().into());
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
    key: InnerKey,
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
                use aes_gcm::aes::Aes128;
                use aes_gcm::aes::cipher::{BlockEncrypt, KeyInit};
                let c = Aes128::new(self.key.as_ref().into());
                let mut sample: [u8; 16] = sample.try_into().unwrap();
                c.encrypt_block((&mut sample).into());
                out.copy_from_slice(&sample[..5]);
            }
            QuicAlgorithm::Aes256 => {
                use aes_gcm::aes::Aes256;
                use aes_gcm::aes::cipher::{BlockEncrypt, KeyInit};
                let c = Aes256::new(self.key.as_ref().into());
                let mut sample: [u8; 16] = sample.try_into().unwrap();
                c.encrypt_block((&mut sample).into());
                out.copy_from_slice(&sample[..5]);
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
        //let rfc_nonce = hex::decode("e0459b3474bdd0e46d417eb0").unwrap();
        let rfc_unprotected_header = hex::decode("4200bff4").unwrap();
        let rfc_payload = hex::decode("01").unwrap();
        //let rfc_payload_ciphertext = hex::decode("655e5cd55c41f69080575d7999c25a5bfb").unwrap();
        let rfc_sample = hex::decode("5e5cd55c41f69080575d7999c25a5bfb").unwrap();
        //let rfc_mask = hex::decode("aefefe7d03").unwrap();
        let rfc_header = hex::decode("4cfe4189").unwrap();
        let rfc_packet = hex::decode("4cfe4189655e5cd55c41f69080575d7999c25a5bfb").unwrap();
        //let rfc_packet_header = &rfc_packet[0..4];
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

    // taken from rustls-openssl
    #[test]
    fn test_aes_test_vector() {
        use rustls::Side;
        use rustls::quic::{Keys, Version};

        // https://www.ietf.org/archive/id/draft-ietf-quic-v2-10.html#name-sample-packet-protection-2
        let icid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let server = Keys::initial(
            Version::V2,
            &TLS13_AES_128_GCM_SHA256_INTERNAL,
            TLS13_AES_128_GCM_SHA256_INTERNAL.quic.unwrap(),
            &icid,
            Side::Server,
        );
        let mut server_payload = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x40, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03,
            0x03, 0xee, 0xfc, 0xe7, 0xf7, 0xb3, 0x7b, 0xa1, 0xd1, 0x63, 0x2e, 0x96, 0x67, 0x78,
            0x25, 0xdd, 0xf7, 0x39, 0x88, 0xcf, 0xc7, 0x98, 0x25, 0xdf, 0x56, 0x6d, 0xc5, 0x43,
            0x0b, 0x9a, 0x04, 0x5a, 0x12, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00,
            0x24, 0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94, 0x0d, 0x89, 0x69, 0x0b, 0x84, 0xd0,
            0x8a, 0x60, 0x99, 0x3c, 0x14, 0x4e, 0xca, 0x68, 0x4d, 0x10, 0x81, 0x28, 0x7c, 0x83,
            0x4d, 0x53, 0x11, 0xbc, 0xf3, 0x2b, 0xb9, 0xda, 0x1a, 0x00, 0x2b, 0x00, 0x02, 0x03,
            0x04,
        ];
        let mut server_header = [
            0xd1, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x00, 0x40, 0x75, 0x00, 0x01,
        ];
        let tag = server
            .local
            .packet
            .encrypt_in_place(1, &server_header, &mut server_payload)
            .unwrap();
        let (first, rest) = server_header.split_at_mut(1);
        let rest_len = rest.len();
        server
            .local
            .header
            .encrypt_in_place(
                &server_payload[2..18],
                &mut first[0],
                &mut rest[rest_len - 2..],
            )
            .unwrap();
        let mut server_packet = server_header.to_vec();
        server_packet.extend(server_payload);
        server_packet.extend(tag.as_ref());
        let expected_server_packet = [
            0xdc, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x00, 0x40, 0x75, 0xd9, 0x2f, 0xaa, 0xf1, 0x6f, 0x05, 0xd8, 0xa4, 0x39, 0x8c,
            0x47, 0x08, 0x96, 0x98, 0xba, 0xee, 0xa2, 0x6b, 0x91, 0xeb, 0x76, 0x1d, 0x9b, 0x89,
            0x23, 0x7b, 0xbf, 0x87, 0x26, 0x30, 0x17, 0x91, 0x53, 0x58, 0x23, 0x00, 0x35, 0xf7,
            0xfd, 0x39, 0x45, 0xd8, 0x89, 0x65, 0xcf, 0x17, 0xf9, 0xaf, 0x6e, 0x16, 0x88, 0x6c,
            0x61, 0xbf, 0xc7, 0x03, 0x10, 0x6f, 0xba, 0xf3, 0xcb, 0x4c, 0xfa, 0x52, 0x38, 0x2d,
            0xd1, 0x6a, 0x39, 0x3e, 0x42, 0x75, 0x75, 0x07, 0x69, 0x80, 0x75, 0xb2, 0xc9, 0x84,
            0xc7, 0x07, 0xf0, 0xa0, 0x81, 0x2d, 0x8c, 0xd5, 0xa6, 0x88, 0x1e, 0xaf, 0x21, 0xce,
            0xda, 0x98, 0xf4, 0xbd, 0x23, 0xf6, 0xfe, 0x1a, 0x3e, 0x2c, 0x43, 0xed, 0xd9, 0xce,
            0x7c, 0xa8, 0x4b, 0xed, 0x85, 0x21, 0xe2, 0xe1, 0x40,
        ];
        assert_eq!(server_packet[..], expected_server_packet[..]);
    }
}
