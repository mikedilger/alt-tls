#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod cert;
pub use cert::SelfSignedCertificateVerifier;

mod sign;
pub use sign::Ed25519Signer;

mod verify;
pub use verify::Ed25519Verifier;
