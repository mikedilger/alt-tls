use crate::hash::Algorithm as HashAlgorithm;
use alloc::boxed::Box;
use hmac::{Hmac, Mac};
use rustls::crypto as rc;
use sha2::Digest;

pub(crate) struct AltHmac(pub(crate) HashAlgorithm);

impl rc::hmac::Hmac for AltHmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn rc::hmac::Key> {
        match self.0 {
            crate::hash::Algorithm::Blake3 => {
                if key.len() > 32 {
                    // If the key is longer than 32 bytes, hash it first and use the hash as
                    // the key
                    let hash = blake3::Hasher::new().update(key).finalize();
                    Box::new(AltHmacKey::Blake3(Box::new(blake3::Hasher::new_keyed(
                        hash.as_bytes(),
                    ))))
                } else {
                    // Otherwise use the key (zero-padded if less than 32 bytes)
                    let mut nkey: [u8; 32] = [0; 32];
                    nkey.copy_from_slice(key);
                    Box::new(AltHmacKey::Blake3(Box::new(blake3::Hasher::new_keyed(
                        &nkey,
                    ))))
                }
            }
            crate::hash::Algorithm::Sha256 => Box::new(AltHmacKey::Sha256(
                Hmac::<sha2::Sha256>::new_from_slice(key).unwrap(),
            )),
            crate::hash::Algorithm::Sha384 => Box::new(AltHmacKey::Sha384(
                Hmac::<sha2::Sha384>::new_from_slice(key).unwrap(),
            )),
        }
    }

    fn hash_output_len(&self) -> usize {
        match self.0 {
            crate::hash::Algorithm::Blake3 => 32,
            crate::hash::Algorithm::Sha256 => sha2::Sha256::output_size(),
            crate::hash::Algorithm::Sha384 => sha2::Sha384::output_size(),
        }
    }
}

pub enum AltHmacKey {
    Blake3(Box<blake3::Hasher>),
    Sha256(hmac::Hmac<sha2::Sha256>),
    Sha384(hmac::Hmac<sha2::Sha384>),
}

impl rc::hmac::Key for AltHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> rc::hmac::Tag {
        match &self {
            AltHmacKey::Blake3(hasher) => {
                let mut ctx = hasher.clone();
                ctx.update(first);
                for m in middle {
                    ctx.update(m);
                }
                ctx.update(last);
                rc::hmac::Tag::new(&ctx.finalize().as_bytes()[..])
            }
            AltHmacKey::Sha256(hmac) => {
                let mut ctx = hmac.clone();
                ctx.update(first);
                for m in middle {
                    ctx.update(m);
                }
                ctx.update(last);
                rc::hmac::Tag::new(&ctx.finalize().into_bytes()[..])
            }
            AltHmacKey::Sha384(hmac) => {
                let mut ctx = hmac.clone();
                ctx.update(first);
                for m in middle {
                    ctx.update(m);
                }
                ctx.update(last);
                rc::hmac::Tag::new(&ctx.finalize().into_bytes()[..])
            }
        }
    }

    fn tag_len(&self) -> usize {
        match self {
            AltHmacKey::Blake3(_) => 32,
            AltHmacKey::Sha256(_) => sha2::Sha256::output_size(),
            AltHmacKey::Sha384(_) => sha2::Sha384::output_size(),
        }
    }
}
