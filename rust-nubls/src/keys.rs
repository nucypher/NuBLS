use bls12_381::{G1Affine, Scalar};

use std::convert::From;

/// A `PublicKey` represents an Affine element of the G_1 group on the BLS12-381 curve.
pub struct PublicKey(G1Affine);

/// A `PrivateKey` represents a Scalar element within the order of the BLS12-381 curve.
pub struct PrivateKey(Scalar);

impl PrivateKey {
    /// Generates a random private key and returns it.
    pub fn random() -> PrivateKey {
        unimplemented!();
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
