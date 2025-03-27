#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod cert;
pub use cert::SelfSignedCertificateVerifier;
