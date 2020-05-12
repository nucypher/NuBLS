use bls12_381::G2Affine;

use crate::keys::{PrivateKey, PublicKey};

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
    /// Returns a `VerificationResult::Valid` if the `message_element` and `public_key`
    /// are correct, and a `VerificationResult::Invalid` if they are not.
    ///
    /// The preferred API to verify signatures is in `public_key.verify`.
    ///
    /// Presently, the API for hashing to the G_2 group of BLS12-381 is not
    /// implemented (see https://github.com/nucypher/NuBLS/issues/1). Therefore,
    /// the message must be prehashed before verification and signing.
    ///
    /// TODO: Implement hash_to_curve.
    pub(crate) fn verify(
        &self,
        public_key: &PublicKey,
        message_element: &G2Affine,
    ) -> VerificationResult {
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
