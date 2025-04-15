use alloc::{boxed::Box, format, string::ToString, sync::Arc, vec::Vec};

use pkcs8::DecodePrivateKey;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, PrivateKeyDer, SignatureVerificationAlgorithm, alg_id,
};
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use sec1::DecodeEcPrivateKey;

#[derive(Clone, Debug)]
pub struct Ed25519Signer(Arc<ed25519_dalek::SigningKey>);

impl TryFrom<&PrivateKeyDer<'_>> for Ed25519Signer {
    type Error = rustls::Error;

    fn try_from(value: &PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        let pkey = match value {
            PrivateKeyDer::Pkcs8(der) => {
                ed25519_dalek::SigningKey::from_pkcs8_der(der.secret_pkcs8_der())
                    .map_err(|e| format!("failed to decrypt private key: {e}"))
            }
            PrivateKeyDer::Sec1(sec1) => {
                ed25519_dalek::SigningKey::from_sec1_der(sec1.secret_sec1_der())
                    .map_err(|e| format!("failed to decrypt private key: {e}"))
            }
            PrivateKeyDer::Pkcs1(_) => Err("ED25519 does not support PKCS#1 key".to_string()),
            _ => Err("not supported".into()),
        };
        pkey.map(|kp| Self(Arc::new(kp)))
            .map_err(rustls::Error::General)
    }
}

impl SigningKey for Ed25519Signer {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&SignatureScheme::ED25519) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        use ed25519_dalek::Signer;

        let sig = self.0.sign(message);
        Ok(sig.to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

#[derive(Debug)]
pub struct Ed25519Verifier;

impl SignatureVerificationAlgorithm for Ed25519Verifier {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        use ed25519_dalek::Verifier;

        let public_key = public_key.try_into().map_err(|_| InvalidSignature)?;
        let signature =
            ed25519_dalek::Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
        ed25519_dalek::VerifyingKey::from_bytes(public_key)
            .map_err(|_| InvalidSignature)?
            .verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }
}
