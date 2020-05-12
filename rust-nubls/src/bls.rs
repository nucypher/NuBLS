use bls12_381::G2Affine;

use crate::keys::PublicKey;

/// A `Signature` is an Affine element of the G_2 group on the BLS12-381 curve.
pub struct Signature(G2Affine);

impl Signature {
    /// Attempts to verify the signature given a `message` and a `public_key`.
    ///
    /// Returns `true` if the signature is valid, and will raise an error if the
    /// signature is invalid.
    pub fn verify(&self) -> bool {
        unimplemented!();
    }
}
