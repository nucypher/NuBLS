use bls12_381::{G1Affine, Scalar};
use getrandom;

use std::convert::From;

/// A `PublicKey` represents an Affine element of the G_1 group on the BLS12-381 curve.
pub struct PublicKey(G1Affine);

/// A `PrivateKey` represents a Scalar element within the order of the BLS12-381 curve.
pub struct PrivateKey(Scalar);

impl PrivateKey {
    /// Generates a random private key and returns it.
    pub fn random() -> PrivateKey {
        let mut key_bytes = [0u8; 64];
        match getrandom::getrandom(&mut key_bytes) {
            Ok(_) => return PrivateKey(Scalar::from_bytes_wide(&key_bytes)),
            Err(error) => panic!("Error while generating a random key: {:?}", error),
        };
    }

    /// Returns the corresponding `PublicKey`.
    pub fn public_key(&self) -> PublicKey {
        unimplemented!();
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(priv_key: PrivateKey) -> Self {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_random() {
        let a = PrivateKey::random();
        let b = PrivateKey::random();

        assert_ne!(a.0, b.0);
    }
}
