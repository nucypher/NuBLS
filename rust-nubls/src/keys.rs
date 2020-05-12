use crate::bls::{Signature, VerificationResult};

use bls12_381::{G1Affine, Scalar};
use getrandom;

use std::convert::From;

/// A `PublicKey` represents an Affine element of the G_1 group on the BLS12-381 curve.
#[derive(Debug, Eq, PartialEq)]
pub struct PublicKey(G1Affine);

/// A `PrivateKey` represents a Scalar element within the order of the BLS12-381 curve.
#[derive(Debug, Eq, PartialEq)]
pub struct PrivateKey(Scalar);

impl PrivateKey {
    /// Generates a random private key and returns it.
    pub fn random() -> PrivateKey {
        let mut key_bytes = [0u8; 64];
        match getrandom::getrandom(&mut key_bytes) {
            Ok(_) => return PrivateKey(Scalar::from_bytes_wide(&key_bytes)),
            Err(err) => panic!("Error while generating a random key: {:?}", err),
        };
    }

    /// Returns the corresponding `PublicKey`.
    pub fn public_key(&self) -> PublicKey {
        PublicKey((&G1Affine::generator() * &self.0).into())
    }

    /// Signs a `message` and returns a `Signature`.
    pub fn sign(&self, message: &[u8]) -> Signature {
        unimplemented!();
    }
}

impl PublicKey {
    /// Attempts to verify a signature.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> VerificationResult {
        signature.verify(message, self)
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(priv_key: PrivateKey) -> Self {
        priv_key.public_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_random() {
        let a = PrivateKey::random();
        let b = PrivateKey::random();

        assert_ne!(a, b);
    }

    fn test_pubkey() {
        let priv_a = PrivateKey::random();
        let pub_a = priv_a.public_key();

        assert_eq!(PublicKey::from(priv_a), pub_a);
        todo!("Get test vectors for the keys");
    }
}
