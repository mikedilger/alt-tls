
#[test]
fn test_key_and_cert_conversions() {
    use ed25519_dalek::SigningKey;

    let mut csprng = rand_core::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    let (certificate_der, _private_key_der) =
        crate::self_signed_tls_identity(&signing_key, vec!["testing".to_owned()]).unwrap();

    let pubkey_extracted = crate::public_key_from_certificate_der(&certificate_der).unwrap();

    assert_eq!(pubkey_extracted, signing_key.verifying_key());
}

#[test]
fn test_data_transfer() {
    use rand::rngs::{OsRng, SmallRng};
    use rand::{Fill, SeedableRng};
    use rustls::{ServerConfig, ClientConfig, KeyLogFile};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::io::{Read, Write};

    pub const ALPN: &[u8] = b"testing";

    let mut csprng = OsRng;

    let server_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
    let server_verifying_key = server_signing_key.verifying_key();
    let client_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);

    let server_config = {
        // Create a certificate verifier that accepts self-signed client certificates
        // using ed25519
        let servers_client_verifier = Arc::new(crate::SelfSignedCertificateVerifier::new(
            crate::SUPPORTED_ALGORITHMS,
            vec![rustls::SignatureScheme::ED25519],
            None, // any client public key is allowed
        ));

        // Create a self-signed TLS identity for server
        let (server_certificate_der, server_private_key_der) = crate::self_signed_tls_identity(
            &server_signing_key,
            vec!["testing".to_string()],
        ).unwrap();

        let mut server_config =
            ServerConfig::builder_with_provider(crate::provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
            .with_client_cert_verifier(servers_client_verifier.clone())
            .with_single_cert(vec![server_certificate_der], server_private_key_der).unwrap();
        server_config.alpn_protocols = vec![ALPN.to_vec()];
        server_config.key_log = Arc::new(KeyLogFile::new());
        Arc::new(server_config)
    };

    let client_config = {
        // Create a certificate verifier that accepts self-signed client certificates
        // using ed25519, requiring the server cert only
        let clients_server_verifier = Arc::new(crate::SelfSignedCertificateVerifier::new(
            crate::SUPPORTED_ALGORITHMS,
            vec![rustls::SignatureScheme::ED25519],
            Some(server_verifying_key.as_bytes().to_vec()), // Must be the expected server
        ));

        // Create a self-signed TLS identity for client
        let (client_certificate_der, client_private_key_der) = crate::self_signed_tls_identity(
            &client_signing_key,
            vec!["testing".to_string()],
        ).unwrap();

        let mut client_config =
            ClientConfig::builder_with_provider(crate::provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
            .dangerous()
            .with_custom_certificate_verifier(clients_server_verifier.clone())
            .with_client_auth_cert(vec![client_certificate_der], client_private_key_der).unwrap();
        client_config.alpn_protocols = vec![ALPN.to_vec()];
        Arc::new(client_config)
    };

    // Server:
    let server_handle = std::thread::spawn(|| {
        let listener = TcpListener::bind("127.99.99.99:4443").unwrap();
        let (mut tcp_stream, _) = listener.accept().unwrap();
        let mut conn = rustls::ServerConnection::new(server_config).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp_stream);

        // WRITE TEST
        let mut seeded_rng = SmallRng::from_seed([0u8; 32]);
        for _ in 0 .. 2 {
            let mut msg = vec![0_u8; 369];
            msg.try_fill(&mut seeded_rng).unwrap();
            tls.write_all(&msg).unwrap();
            tls.flush().unwrap();
        }
        tls.conn.send_close_notify();
        tls.flush().unwrap();

        let mut bye = [0; 4];
        tls.read(&mut bye).unwrap();
    });

    let server_name = "127.99.99.99".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
    let mut sock = TcpStream::connect("127.99.99.99:4443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let mut transmitted = Vec::new();
    tls.read_to_end(&mut transmitted).unwrap();

    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
    assert_eq!(ciphersuite.suite(), rustls::CipherSuite::Unknown(crate::tls13::IANA_CIPHER_SUITE));

    let mut seeded_rng = SmallRng::from_seed([0u8; 32]);
    let mut proper = vec![0_u8; transmitted.len()];
    proper.try_fill(&mut seeded_rng).unwrap();

    tls.write_all(b"BYE").unwrap();
    tls.conn.send_close_notify();
    tls.flush().unwrap();

    server_handle.join().unwrap();

    // Compare transmitted adn proper
    for i in 0..proper.len() {
        assert!(transmitted[i] == proper[i], "Fails at byte {i}");
    }
}

