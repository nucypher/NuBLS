# NuBLS
![Crates.io](https://img.shields.io/crates/l/nubls)
![Discord](https://img.shields.io/discord/411401661714792449)

NuBLS is NuCypher's BLS signature library that implements threshold protocols
like threshold signatures and a Proxy Re-Signature (PRS) algorithm designed
by NuCypher called Penumbral.

The NuBLS library offers bindings to Python from a rust backend, see below for
details.

## Rust
![Crates.io](https://img.shields.io/crates/v/nubls)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/nucypher/nubls/rust)

The core of NuBLS is written in Rust, and is accessible here - https://github.com/nucypher/NuBLS/tree/master/rust-nubls

## Python
![PyPI](https://img.shields.io/pypi/v/pynubls)

The Python bindings are also written in Rust using the PyO3 library to ensure
safety. This crate is accessible here - https://github.com/nucypher/NuBLS/tree/master/nubls/src

### Installation
You can install NuBLS from pip with: `pip install pynubls`. Alternatively, see
the build instructions below.

### Building PyNuBLS
To build `pynubls` for Python, create a virtual environment and install maturin:
`pip install maturin`

Then build the package with:
`maturin build`

To build and install the package into your virtual environment use:
`maturin develop`

### Usage
The API for the Python wrapper closely resembles that of the Rust API. After
installing via pip or building the development version, you can call it in Python with:
```python
from pynubls import PrivateKey, PublicKey, hash_message, InvalidSignature

priv_key = PrivateKey.random()
pub_key = priv_key.public_key()

priv_key_bytes = priv_key.to_bytes()
pub_key_bytes = pub_key.to_bytes()

# Splitting/Recovery
key_frags = priv_key.split(3, 5)
recovered_key = PrivateKey.recover(key_frags[:3])

# Signing
sig = priv_key.sign(hash_message(b'NuBLS!'))
try:
    pub_key.verify(hash_message(b'NuBLS!'), sig)
except InvalidSignature:
    # Raises `InvalidSignature` when the signature is invalid.
    print("The signature is invalid.")

# Penumbral Proxy Re-Signature
alice_priv, bob_priv = PrivateKey.random(), PrivateKey.random()

resigning_key_bob_to_alice = alice_priv.resigning_key(bob_priv.public_key())
sig_under_bob = bob_priv.designated_key(alice_priv.public_key()).sign(hash_message(b'Penumbral!'))

resigned_sig = resigning_key_bob_to_alice.resign(sig_under_bob)
alice_priv.public_key().verify(hash_message(b'Penumbral!'), resigned_sig)
```

### Warning
As this library is a work-in-progress, there are some missing API details.
One of these is a rust-native hash-to-curve implementation. As such, it's not
presently possible to hash messages natively with this library, and another
library must be used. To get around this, `pynubls` uses the `py-ecc` library
for hashing messages to the curve.
