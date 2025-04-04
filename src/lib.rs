#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "std"))]
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use core::ops::Deref;
#[cfg(feature = "std")]
use std::boxed::Box;

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use rcgen::{CertificateParams, KeyPair};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::PrivateKeyDer;
use rustls::{
    CipherSuite, CipherSuiteCommon, SignatureScheme, SupportedCipherSuite, Tls13CipherSuite,
};

mod aead;

mod cert;
pub use cert::SelfSignedCertificateVerifier;

mod hash;

mod hmac;

pub mod hpke;

mod kx;

mod sign;
pub use sign::Ed25519Signer;

mod verify;
pub use verify::Ed25519Verifier;

#[cfg(feature = "std")]
/// This generates a self-signed certificate from an ed25519 private signing key
pub fn certificate_pem(signing_key: &SigningKey) -> Result<String, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let signing_key_pem = signing_key.to_pkcs8_pem(LineEnding::LF)?;
    let rcgen_keypair = KeyPair::from_pem(signing_key_pem.deref())?;

    let cert = CertificateParams::new(vec![
        "IGNORE THE NAME, DETERMINE TRUST FROM THE KEY".to_string(),
    ])?
    .self_signed(&rcgen_keypair)?;

    Ok(cert.pem())
}

#[cfg(not(feature = "std"))]
/// This generates a self-signed certificate from an ed25519 private signing key
pub fn certificate_pem(signing_key: &SigningKey) -> Result<String, String> {
    let signing_key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("{e}"))?;
    let rcgen_keypair = KeyPair::from_pem(signing_key_pem.deref()).map_err(|e| format!("{e}"))?;

    let cert = CertificateParams::new(vec![
        "IGNORE THE NAME, DETERMINE TRUST FROM THE KEY".to_string(),
    ])
    .map_err(|e| format!("{e}"))?
    .self_signed(&rcgen_keypair)
    .map_err(|e| format!("{e}"))?;

    Ok(cert.pem())
}

/// This supplies a rustls `CryptoProvider` that works with a very restricted
/// configuration:
///
/// * TLS is 1.3 only
/// * Signature algorithm/scheme is ED25519 only
/// * AEAD is chacha20-poly1305 only
/// * Hash is SHA256 only
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

pub const SUPPORTED_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[&Ed25519Verifier],
    mapping: &[(SignatureScheme::ED25519, &[&Ed25519Verifier])],
};

// We currently use a 'reserved for private use' number. Get one assigned.
// See: https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-4
const IANA_CIPHER_SUITE: u16 = 0xFFED;

#[derive(Debug)]
struct Provider;

static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS13_CHACHA20_POLY1305_BLAKE3,
    TLS13_CHACHA20_POLY1305_SHA256,
];

pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Chacha20Poly1305,
        quic: None, // FIXME
    });

pub static TLS13_CHACHA20_POLY1305_BLAKE3: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::Unknown(IANA_CIPHER_SUITE),
            hash_provider: &hash::Blake3,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::Blake3),
        aead_alg: &aead::Chacha20Poly1305,
        quic: None, // FIXME
    });

impl rustls::crypto::SecureRandom for Provider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| rustls::crypto::GetRandomFailed)
    }
}

impl rustls::crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        Ok(Arc::new(sign::Ed25519Signer::try_from(&key_der).map_err(
            |err| {
                #[cfg(feature = "std")]
                let err = rustls::OtherError(Arc::new(err));
                #[cfg(not(feature = "std"))]
                let err = rustls::Error::General(alloc::format!("{}", err));
                err
            },
        )?))
    }
}
