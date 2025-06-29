use crate::{aead, hash, hmac, quic};
pub use rustls::SupportedCipherSuite;
use rustls::{CipherSuite, CipherSuiteCommon, Tls13CipherSuite};

// We currently use a 'reserved for private use' number. Get one assigned.
// See: https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-4
const IANA_CIPHER_SUITE: u16 = 0xFFED;

pub static TLS13_CHACHA20_POLY1305_BLAKE3: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&TLS13_CHACHA20_POLY1305_BLAKE3_INTERNAL);

pub(crate) static TLS13_CHACHA20_POLY1305_BLAKE3_INTERNAL: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::Unknown(IANA_CIPHER_SUITE),
        hash_provider: &hash::Algorithm::Blake3,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::AltHmac(hash::Algorithm::Blake3)),
    aead_alg: &aead::chacha20::Chacha20Poly1305,
    quic: Some(&quic::QuicAlgorithm::ChaCha),
};

pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&TLS13_CHACHA20_POLY1305_SHA256_INTERNAL);

pub(crate) static TLS13_CHACHA20_POLY1305_SHA256_INTERNAL: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &hash::Algorithm::Sha256,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::AltHmac(hash::Algorithm::Sha256)),
    aead_alg: &aead::chacha20::Chacha20Poly1305,
    quic: Some(&quic::QuicAlgorithm::ChaCha),
};

pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&TLS13_AES_128_GCM_SHA256_INTERNAL);

pub(crate) static TLS13_AES_128_GCM_SHA256_INTERNAL: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &hash::Algorithm::Sha256,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::AltHmac(hash::Algorithm::Sha256)),
    aead_alg: &aead::gcm::Tls13Aes128Gcm,
    quic: Some(&quic::QuicAlgorithm::Aes128),
};

pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&TLS13_AES_256_GCM_SHA384_INTERNAL);

pub(crate) static TLS13_AES_256_GCM_SHA384_INTERNAL: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: &hash::Algorithm::Sha384,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::AltHmac(hash::Algorithm::Sha384)),
    aead_alg: &aead::gcm::Tls13Aes256Gcm,
    quic: Some(&quic::QuicAlgorithm::Aes256),
};
