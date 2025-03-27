use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use rcgen::{CertificateParams, KeyPair};
use std::env;
use std::ops::Deref;

#[cfg(target_os = "windows")]
const LINE_ENDING: LineEnding = LineEnding::CRLF;
#[cfg(target_os = "macos")]
const LINE_ENDING: LineEnding = LineEnding::CR;
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
const LINE_ENDING: LineEnding = LineEnding::LF;

fn main() {
    eprintln!("WARNING: This just prints secrets to your console. Use as example only.\n");

    let mut args = env::args();
    let _ = args.next().unwrap();
    let secret_key_hex = match args.next() {
        Some(a) => a,
        None => panic!("USAGE: import_ed25519_identity <hex_secret_key>"),
    };
    let secret_key_bytes = hex::decode(secret_key_hex).unwrap();
    let signing_key = SigningKey::from_bytes(secret_key_bytes[0..32].try_into().unwrap());

    println!(
        "PRIVATE SIGNING KEY (hex):\n{}\n",
        hex::encode(signing_key.as_bytes())
    );
    println!(
        "PUBLIC VERIFYING KEY (hex):\n{}\n",
        hex::encode(signing_key.verifying_key().as_bytes())
    );
    let signing_key_pem = signing_key.to_pkcs8_pem(LINE_ENDING).unwrap();
    println!(
        "PRIVATE SIGNING KEY (pem, pkcs8v2):\n{}\n",
        signing_key_pem.deref()
    );

    // self signed certificate in PEM
    let rcgen_keypair = KeyPair::from_pem(signing_key_pem.deref()).unwrap();
    let cert = CertificateParams::new(vec![
        "IGNORE THE NAME, DETERMINE TRUST FROM THE KEY".to_string(),
    ])
    .unwrap()
    .self_signed(&rcgen_keypair)
    .unwrap();

    println!("PUBLIC SELF-SIGNED CERTIFICATE (pem):\n{}\n", cert.pem());
}
