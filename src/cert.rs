use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::Deref;

use rustls::client::danger;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// This is a certificate verifier that allows all self-signed certificates.
/// It does NOT require any particular known certificate; rather, any self-signed certificate
/// will be considered valid so long as the self-signature matches the key.
///
/// The Distinguished Name within the certificate is UTTERLY UNTRUSTWORTHY when using
/// this verifier. You MUST instead consider only the public key from the certificate as the
/// counterparty and act accordingly.
#[derive(Debug)]
pub struct SelfSignedCertificateVerifier {
    algorithms: WebPkiSupportedAlgorithms,
    schemes: Vec<SignatureScheme>,
    expected_key_bytes: Option<Vec<u8>>,
}

impl SelfSignedCertificateVerifier {
    /// Create a new `SelfSignedCertificateVerifier` supporting the specified
    /// algorithms and signature schemes
    pub fn new(
        algorithms: WebPkiSupportedAlgorithms,
        schemes: Vec<SignatureScheme>,
        expected_key_bytes: Option<Vec<u8>>,
    ) -> SelfSignedCertificateVerifier {
        SelfSignedCertificateVerifier {
            algorithms,
            schemes,
            expected_key_bytes,
        }
    }
}

impl danger::ServerCertVerifier for SelfSignedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<danger::ServerCertVerified, rustls::Error> {
        if let Some(expected_key_bytes) = &self.expected_key_bytes {
            let (_, cert) = x509_parser::parse_x509_certificate(end_entity.deref())
                .map_err(|e| rustls::Error::Other(rustls::OtherError(Arc::new(e))))?;

            // We don't need constant time compare, this is a public key
            if expected_key_bytes != cert.tbs_certificate.subject_pki.subject_public_key.as_ref() {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Other(rustls::OtherError(Arc::new(
                        rustls::Error::General("Public Key Mismatch".to_string()),
                    ))),
                ));
            }
        }

        Ok(danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}
