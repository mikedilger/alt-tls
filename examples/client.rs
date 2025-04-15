use rustls::ClientConfig;
use std::io::{Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

const PORT: u32 = 4433;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let server_public_key =
        hex::decode("4ce5c72e946f0de39f431ae371c8b29b3d9eec992e71c53fb79f7022c0f2d0a0")?;

    let verifier = Arc::new(alt_tls::SelfSignedCertificateVerifier::new(
        alt_tls::SUPPORTED_ALGORITHMS,
        vec![rustls::SignatureScheme::ED25519],
        Some(server_public_key),
    ));

    let client_config = {
        let mut client_config = ClientConfig::builder_with_provider(alt_tls::provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();

        client_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Arc::new(client_config)
    };

    let server_name = "localhost".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(client_config.clone(), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("[::]:{}", PORT)).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: localhost\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();

    Ok(())
}
