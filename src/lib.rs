#![cfg_attr(not(test), no_std)]

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

mod aead;
mod cert;
pub use cert::SelfSignedCertificateVerifier;
mod ed25519;
pub use ed25519::{Ed25519Signer, Ed25519Verifier};
mod error;
pub use error::Error;
mod hash;
mod hmac;
pub mod hpke;
mod quic;
mod tls13;
pub use tls13::*;
mod x25519;

pub use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
pub use ed25519_dalek::pkcs8::spki::der::zeroize::Zeroizing;
use rcgen::{CertificateParams, KeyPair};
use rustls::SignatureScheme;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// This generates a self-signed certificate from an ed25519 private signing key
pub fn certificate_pem(signing_key: &SigningKey) -> Result<String, Error> {
    let signing_key_pem = signing_key.to_pkcs8_pem(LineEnding::LF)?;
    let rcgen_keypair = KeyPair::from_pem(signing_key_pem.deref())?;

    let cert = CertificateParams::new(vec![
        "IGNORE THE NAME, DETERMINE TRUST FROM THE KEY".to_string(),
    ])?
    .self_signed(&rcgen_keypair)?;

    Ok(cert.pem())
}

/// This generates a self-signed CertificateDer and PrivateKeyDer for use with rustls
/// as either server or client-side identity
pub fn self_signed_tls_identity(
    signing_key: &SigningKey,
    distinguished_names: vec::Vec<String>,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Error> {
    let private_key_der = {
        let dalek_secret_document_der = signing_key.to_pkcs8_der()?;
        let private_pkcs8_key_der: PrivatePkcs8KeyDer<'_> =
            dalek_secret_document_der.as_bytes().into();
        let private_pkcs8_key_der: PrivatePkcs8KeyDer<'static> = private_pkcs8_key_der.clone_key();
        PrivateKeyDer::Pkcs8(private_pkcs8_key_der)
    };

    let certificate_der = {
        use crate::alloc::borrow::ToOwned;
        let certificate_params = CertificateParams::new(distinguished_names)?;
        let key_pair = KeyPair::try_from(&private_key_der)?;
        let certificate = certificate_params.self_signed(&key_pair)?;
        certificate.der().to_owned()
    };

    Ok((certificate_der, private_key_der))
}

// cert_chain: Vec<CertificateDer<'static>>,
// key_der: PrivateKeyDer<'static>,

/// This supplies a rustls `CryptoProvider` that works with a very restricted
/// configuration:
///
/// * TLS is 1.3 only
/// * Signature algorithm/scheme is ED25519 only
/// * Cipher suites supported include
///     * TLS13_CHACHA20_POLY1305_BLAKE3 (non standard)
///     * TLS13_CHACHA20_POLY1305_SHA256
///     * TLS13_AES_256_GCM_SHA384
///     * TLS13_AES_128_GCM_SHA256
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: x25519::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

/// This supplies a rustls `CryptoProvider` that works with a very restricted
/// configuration, and lets you specify your preferred cipher suites:
///
/// * TLS is 1.3 only
/// * Signature algorithm/scheme is ED25519 only
pub fn configured_provider(
    cipher_suites: vec::Vec<rustls::SupportedCipherSuite>,
) -> CryptoProvider {
    CryptoProvider {
        cipher_suites,
        kx_groups: x25519::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

pub const SUPPORTED_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[&Ed25519Verifier],
    mapping: &[(SignatureScheme::ED25519, &[&Ed25519Verifier])],
};

#[derive(Debug)]
struct Provider;

pub static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    tls13::TLS13_CHACHA20_POLY1305_BLAKE3,
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
];

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
        Ok(Arc::new(Ed25519Signer::try_from(&key_der).map_err(
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
