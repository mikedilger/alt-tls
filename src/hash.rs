use alloc::boxed::Box;
use rustls::crypto as rc;
use sha2::Digest;

// We currently use a 'reserved for private use' number. Get one assigned.
// See: https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-18
const IANA_BLAKE3_HASH_ALGORITHM_CODE: u8 = 230;

/// Supported Hash algorithms.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Algorithm {
    Blake3,
    Sha256,
    #[allow(dead_code)]
    Sha384,
}

/// A Hash context
#[derive(Clone)]
enum Context {
    Blake3(blake3::Hasher),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
}

impl rc::hash::Hash for Algorithm {
    fn start(&self) -> Box<dyn rc::hash::Context> {
        match &self {
            Algorithm::Blake3 => Box::new(Context::Blake3(blake3::Hasher::new())),
            Algorithm::Sha256 => Box::new(Context::Sha256(sha2::Sha256::new())),
            Algorithm::Sha384 => Box::new(Context::Sha384(sha2::Sha384::new())),
        }
    }

    fn hash(&self, data: &[u8]) -> rc::hash::Output {
        match &self {
            Algorithm::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(data);
                rc::hash::Output::new(hasher.finalize().as_bytes().as_slice())
            },
            Algorithm::Sha256 => {
                rc::hash::Output::new(&sha2::Sha256::digest(data)[..])
            },
            Algorithm::Sha384 => {
                rc::hash::Output::new(&sha2::Sha384::digest(data)[..])
            },
        }
    }

    fn algorithm(&self) -> rc::hash::HashAlgorithm {
        match &self {
            Algorithm::Blake3 => rc::hash::HashAlgorithm::Unknown(
                IANA_BLAKE3_HASH_ALGORITHM_CODE
            ),
            Algorithm::Sha256 => rc::hash::HashAlgorithm::SHA256,
            Algorithm::Sha384 => rc::hash::HashAlgorithm::SHA384,
        }
    }

    fn output_len(&self) -> usize {
        32
    }
}

impl Context {
    fn finish_inner(self) -> rc::hash::Output {
        match self {
            Self::Blake3(context) => rc::hash::Output::new(
                context.finalize().as_bytes().as_slice()
            ),
            Self::Sha256(context) => rc::hash::Output::new(&context.finalize()[..]),
            Self::Sha384(context) => rc::hash::Output::new(&context.finalize()[..]),
        }
    }

}

impl rc::hash::Context for Context {
    fn fork_finish(&self) -> rc::hash::Output {
        let new_context = Box::new(self.clone());
        new_context.finish_inner()
    }

    fn fork(&self) -> Box<dyn rc::hash::Context> {
        Box::new(self.clone())
    }

    fn finish(self: Box<Self>) -> rc::hash::Output {
        self.finish_inner()
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Blake3(context) => {
                context.update(data);
            },
            Self::Sha256(context) => context.update(data),
            Self::Sha384(context) => context.update(data),
        }
    }
}
