use alloc::boxed::Box;

use hmac::{Hmac, Mac};
use rustls::crypto;
use sha2::{Digest, Sha256};

pub struct Sha256Hmac;

impl crypto::hmac::Hmac for Sha256Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(Sha256HmacKey(Hmac::<Sha256>::new_from_slice(key).unwrap()))
    }

    fn hash_output_len(&self) -> usize {
        Sha256::output_size()
    }
}

struct Sha256HmacKey(Hmac<Sha256>);

impl crypto::hmac::Key for Sha256HmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut ctx = self.0.clone();
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        crypto::hmac::Tag::new(&ctx.finalize().into_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        Sha256::output_size()
    }
}

pub(crate) use crate::hash::{Blake3, Blake3Context};

impl crypto::hmac::Hmac for Blake3 {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        if key.len() > 32 {
            // If the key is longer than 32 bytes, hash it first and use the hash as
            // the key
            let hash = blake3::Hasher::new().update(key).finalize();
            Box::new(Blake3Context(blake3::Hasher::new_keyed(hash.as_bytes())))
        } else {
            // Otherwise use the key (zero-padded if less than 32 bytes)
            let mut nkey: [u8; 32] = [0; 32];
            nkey.copy_from_slice(key);
            Box::new(Blake3Context(blake3::Hasher::new_keyed(&nkey)))
        }
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

impl crypto::hmac::Key for Blake3Context {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut ctx = self.0.clone();
        ctx.update(first);
        for m in middle {
            ctx.update(m);
        }
        ctx.update(last);
        crypto::hmac::Tag::new(&ctx.finalize().as_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        32
    }
}
