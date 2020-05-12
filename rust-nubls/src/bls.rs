use bls12_381::G2Affine;

use crate::keys::PublicKey;

use std::convert::From;

/// This type represents the output of a Signature verification.
///
/// By representing signature verification in an `enum` like this, we are able
/// to construct a safe, misuse resistant API by forcing the user to handle
/// both cases of signature verification logic (Valid/Invalid). This prevents
/// silent failures that otherwise may be present when APIs return `bool`s.
pub enum VerificationResult {
    Valid,
    Invalid,
}

/// A `Signature` is an Affine element of the G_2 group on the BLS12-381 curve.
pub struct Signature(G2Affine);

impl Signature {
    /// Attempts to verify the signature given a `message` and a `public_key`.
    /// Returns `true` if the signature is valid and `false` if the signature is invalid.
    ///
    /// The preferred API to verify signatures is in `public_key.verify`.
    pub(crate) fn verify(&self, message: &[u8], public_key: &PublicKey) -> VerificationResult {
        unimplemented!();
    }
}

impl From<bool> for VerificationResult {
    fn from(result: bool) -> Self {
        if result {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid
        }
    }
}
