# alt-tls

This crate provides TLS configurations usable by [rustls](https://crates.io/crates/rustls)
that support the modern ed25519 signature scheme and x25519 key exchange, and also blake3
for hashing and HMAC substitution.

## Identity Management

Two binaries are provided: `generate_ed25519_identity` and `import_ed25519_identity`
which generate (or import from hex) ed25519 secret signing key identities, and outputs
the key in hex, in PEM, and also as a self-signed certificate in PEM.

The certificate generated has af Distinguised Name with an alternate name
that simply reads "IGNORE THE NAME, DETERMINE TRUST FROM THE KEY".

## TLS

We provide a TLS provider by calling `provider()` which internally provides and
supports a very limited TLS configuration:

* TLS 1.3 only
* Signature algorithm is ed25519 only
* AEAD is chacha20-poly1305 only
* Hash is SHA256 or Blake3 only
* HMAC is SHA256 or Blake3 (directly using blake3 keyed hash, not HMAC construction)

You can run the `example/server.rs` and `example/client.rs` and they will talk to
each other over TLS using our provider.

## Debugging / Inspecting

For deeper inspection into the TLS you can set some environment varibles when you run
the examples, e.g.

```
$ RUST_LOG=rustls=trace SSLKEYLOGFILE=sslkeys-server.log cargo run --example server
$ RUST_LOG=rustls=trace SSLKEYLOGFILE=sslkeys-client.log cargo run --example client
```

## HPKE

HPKE [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) standardizes public key
encryption. We expose a copy of the rustls implementation of an HPKE provider.
DHKEM_X25519_HKDF_SHA256_CHACHA20_POLY1305 looks nice.

What is an HPKE? It is a newly standardized way to send an encrypted message to someone
when you just know their public key, adopted into TLS and elsewhere. Previously we had
a lot of incompatible implementations like BouncyCastle, NaCl box, etc.

## TODO

* Support for secp256k1
* Figure out why rustls providers for TLS 1.3 don't specify (nor can use) ECDHE or PSK
