use alloc::boxed::Box;
use rustls::crypto::{self, hash};

// We currently use a 'reserved for private use' number. Get one assigned.
// See: https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-18
const IANA_BLAKE3_HASH_ALGORITHM_CODE: u8 = 230;

pub(crate) struct Blake3;

impl hash::Hash for Blake3 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Blake3Context(blake3::Hasher::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        hash::Output::new(hasher.finalize().as_bytes().as_slice())
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::Unknown(IANA_BLAKE3_HASH_ALGORITHM_CODE)
    }

    fn output_len(&self) -> usize {
        32
    }
}

pub(crate) struct Blake3Context(pub(crate) blake3::Hasher);

impl hash::Context for Blake3Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(self.0.clone().finalize().as_bytes().as_slice())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Blake3Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(self.0.finalize().as_bytes().as_slice())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

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
