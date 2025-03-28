use alloc::boxed::Box;

use rustls::crypto::hash;
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

// We currently use a 'reserved for private use' number. Get one assigned.
// See: https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-18
const IANA_HASH_ALGORITHM_CODE: u8 = 230;

pub struct Blake3;

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
        hash::HashAlgorithm::Unknown(IANA_HASH_ALGORITHM_CODE)
    }

    fn output_len(&self) -> usize {
        32
    }
}

struct Blake3Context(blake3::Hasher);

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
