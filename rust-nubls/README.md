# NuBLS
![Crates.io](https://img.shields.io/crates/v/nubls)
![Crates.io](https://img.shields.io/crates/l/nubls)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/nucypher/nubls/rust)
![Discord](https://img.shields.io/discord/411401661714792449)

The `nubls` crate is a Rust implentation of BLS signatures on BLS12-381.
This implementation aims to follow [the IETF Draft BLS Specification](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02).

This library aims to be `no_std` ready, but isn't quite there yet.

## Documentation
[See the documentation on crates.io!](https://docs.rs/nubls)

### Penumbral Proxy Re-Signature
Penumbral is NuCypher's Threshold Proxy Re-Signature (PRS) algorithm.

Proxy Re-Signature is a type of algorithm that allows signatures under one key
to be transformed into signatures under another key by a third party who uses
a "Re-Signing key". This ensures that the third party never has access to either
private key.

The Penumbral paper is a work-in-progress, but will be published shortly.

For usage details, see the tests here -- https://github.com/nucypher/NuBLS/blob/master/rust-nubls/src/keys.rs#L484

### Signing
For usage details, see the tests here -- https://github.com/nucypher/NuBLS/blob/master/rust-nubls/src/keys.rs#L399

### Threshold Splitting/Recovery
For usage details, see the tests here -- https://github.com/nucypher/NuBLS/blob/master/rust-nubls/src/keys.rs#L321

### Warning
As this library is a work-in-progress, there are some missing API details.
One of these is a rust-native hash-to-curve implementation. As such, it's not
presently possible to hash messages natively with this library, and another
library must be used.
