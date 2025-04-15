use alloc::boxed::Box;
use hmac::{Hmac, Mac};
use rustls::crypto::{self, hash};
use sha2::Digest;

pub struct Sha256;

impl hash::Hash for Sha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(sha2::Sha256::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&sha2::Sha256::digest(data)[..])
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }

    fn output_len(&self) -> usize {
        32
    }
}

struct Sha256Context(sha2::Sha256);

impl hash::Context for Sha256Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize()[..])
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

pub struct Sha256Hmac;

impl crypto::hmac::Hmac for Sha256Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(Sha256HmacKey(
            Hmac::<sha2::Sha256>::new_from_slice(key).unwrap(),
        ))
    }

    fn hash_output_len(&self) -> usize {
        sha2::Sha256::output_size()
    }
}

struct Sha256HmacKey(Hmac<sha2::Sha256>);

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
        sha2::Sha256::output_size()
    }
}
