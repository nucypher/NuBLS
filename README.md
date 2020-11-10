# NuBLS
NuBLS is NuCypher's BLS signature library that implements threshold protocols
like threshold signatures and a Proxy Re-Signature (PRS) algorithm designed
by NuCypher called Penumbral.

The NuBLS library offers bindings to Python from a rust backend, see below for
details.

## Rust
The core of NuBLS is written in Rust, and is accessible here - https://github.com/nucypher/NuBLS/tree/master/rust-nubls

## Python
The Python bindings are also written in Rust using the PyO3 library to ensure
safety. This crate is accessible here - https://github.com/nucypher/NuBLS/tree/master/nubls/src

## Documentation
See each crate's respective repository for Documentation details.

### Warning
As this library is a work-in-progress, there are some missing API details.
One of these is a rust-native hash-to-curve implementation. As such, it's not
presently possible to hash messages natively with this library, and another
library must be used.
