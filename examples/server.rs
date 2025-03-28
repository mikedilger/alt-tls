use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::Acceptor;
use std::io::Write;
use std::sync::Arc;

const PORT: u32 = 4433;

const PRIVATE_KEY_PEM: &'static [u8] = b"
-----BEGIN PRIVATE KEY-----
MFECAQEwBQYDK2VwBCIEIEzcSZK1f14Woeyb+hEa0t+BLVVRBT5oEm4TnsCBt6fc
gSEAZVTJPNuHiMQTcVpRkVsdlkzZhjPOdeOLNsYmVGwJuLM=
-----END PRIVATE KEY-----
";

const CERTIFICATE_PEM: &'static [u8] = b"
-----BEGIN CERTIFICATE-----
MIIBQTCB9KADAgECAhRE5YzN5ciBbjGUADT9eCOLEbZ7+DAFBgMrZXAwITEfMB0G
A1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDAgFw03NTAxMDEwMDAwMDBaGA80
MDk2MDEwMTAwMDAwMFowITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2Vy
dDAqMAUGAytlcAMhAGVUyTzbh4jEE3FaUZFbHZZM2YYzznXjizbGJlRsCbizozww
OjA4BgNVHREEMTAvgi1JR05PUkUgVEhFIE5BTUUsIERFVEVSTUlORSBUUlVTVCBG
Uk9NIFRIRSBLRVkwBQYDK2VwA0EA2ogCc5avzvF76z4o/hjweAZSCsOfU1M1kghx
KbCOyq3OOnogDeQG4EOiA/DFCZ4tUDSE1H3y5cj282oi466MDQ==
-----END CERTIFICATE-----
";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let server_config = {
        let private_key = PrivateKeyDer::from_pem_slice(PRIVATE_KEY_PEM).unwrap();
        let cert = CertificateDer::from_pem_slice(CERTIFICATE_PEM).unwrap();

        let mut server_config = ServerConfig::builder_with_provider(alt_tls::provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![cert], private_key)
            .unwrap();

        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Arc::new(server_config)
    };

    let listener = std::net::TcpListener::bind(format!("[::]:{}", PORT)).unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };

        match accepted.into_connection(server_config.clone()) {
            Ok(mut conn) => {
                let msg = concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Connection: Closed\r\n",
                    "Content-Type: text/html\r\n",
                    "\r\n",
                    "<h1>Hello World!</h1>\r\n"
                )
                .as_bytes();

                // Note: do not use `unwrap()` on IO in real programs!
                conn.writer().write_all(msg).unwrap();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();

                conn.send_close_notify();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();
            }
            Err((err, _)) => {
                eprintln!("{err}");
            }
        }
    }

    Ok(())
}
