# alt-tls

This crate provides TLS configurations usable by [rustls](https://crates.io/crates/rustls)
that support the modern ed25519 signature scheme and x25519 key exchange.

We intend to also eventually support blake3 and secp256k1 (bitcoin/nostr) if feasible.

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

## TODO

* Support for secp256k1
* Look at what hpke is for, and add if useful
* Figure out why rustls providers for TLS 1.3 don't specify (nor can use) ECDHE or PSK
