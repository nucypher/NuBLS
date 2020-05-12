use crate::bls::{Signature, VerificationResult};

use bls12_381::{G1Affine, G2Affine, Scalar};
use getrandom;

use std::convert::From;

/// A `PublicKey` represents an Affine element of the G_1 group on the BLS12-381 curve.
#[derive(Debug, Eq, PartialEq)]
pub struct PublicKey(pub(crate) G1Affine);

/// A `PrivateKey` represents a Scalar element within the order of the BLS12-381 curve.
#[derive(Debug, Eq, PartialEq)]
pub struct PrivateKey(pub(crate) Scalar);

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
        // The BLS12_381 API doesn't work with additive notation, apparently.
        PublicKey((&G1Affine::generator() * &self.0).into())
    }

    /// Signs a `message_element` and returns a Signature.
    ///
    /// The `sign` API presently only works with messages already mapped to the
    /// G_2 group on BLS12-381 (see https://github.com/nucypher/NuBLS/issues/1).
    ///
    /// TODO: Implement `hash_to_curve` per the IETF hash_to_curve specification.
    pub fn sign(&self, message_element: &G2Affine) -> Signature {
        Signature::new(self, message_element)
    }
}

impl PublicKey {
    /// Attempts to verify a signature given a `message_element` and a `signature`.
    ///
    /// The `verify` API presently only works with messages already mapped to the
    /// G_2 group on BLS12-381 (see https://github.com/nucypher/NuBLS/issues/1).
    ///
    /// TODO: Implement `hash_to_curve` per the IETF hash_to_curve specification.
    pub fn verify(&self, message_element: &G2Affine, signature: &Signature) -> VerificationResult {
        signature.verify(self, message_element)
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

    #[test]
    fn test_random() {
        let a = PrivateKey::random();
        let b = PrivateKey::random();

        assert_ne!(a, b);
    }

    #[test]
    fn test_pubkey() {
        let priv_a = PrivateKey::random();
        let pub_a = priv_a.public_key();

        assert_eq!(PublicKey::from(priv_a), pub_a);
        // TODO: Get test vectors (see https://github.com/nucypher/NuBLS/issues/2)
    }

    #[test]
    fn test_signing_and_verifying() {
        let priv_a = PrivateKey::random();
        let pub_a = priv_a.public_key();

        // Generate and sign a random message to sign in G_2.
        let rand = PrivateKey::random();
        let msg = G2Affine::from(G2Affine::generator() * &rand.0);

        let sig_msg = priv_a.sign(&msg);
        assert_eq!(sig_msg, Signature::new(&priv_a, &msg));

        // Check that the message is valid
        let verified = pub_a.verify(&msg, &sig_msg);
        assert_eq!(verified, sig_msg.verify(&pub_a, &msg));
        assert_eq!(verified, VerificationResult::Valid);

        // Generate a random invalid message for `sig_msg` and check that it
        // is invalid.
        let new_rand = PrivateKey::random();
        let bad_msg = G2Affine::from(G2Affine::generator() * &new_rand.0);
        assert_ne!(bad_msg, msg);

        let not_verified = pub_a.verify(&bad_msg, &sig_msg);
        assert_eq!(not_verified, VerificationResult::Invalid);
    }

    #[test]
    fn test_verification_result_handling() {
        // This test demonstrates the misuse-resistant signature verification
        // API. This is how a user should handle signature verification logic
        // within their own application.
        let priv_a = PrivateKey::random();
        let pub_a = priv_a.public_key();

        // Generate and sign a random message to sign in G_2.
        let rand = PrivateKey::random();
        let msg = G2Affine::from(G2Affine::generator() * &rand.0);
        let sig_msg = priv_a.sign(&msg);

        // We define a function that handles the logic of a signature verification
        // and returns a string depending on if it verified or not.
        //
        // Notice how we use pattern matching to handle the signature verification
        // result; if we don't handle both cases (Valid/Invalid), this will not compile.
        // This forces users to properly handle signature verification.
        fn handle_signature_verification(is_verified: &VerificationResult) -> &str {
            match is_verified {
                VerificationResult::Valid => "Valid message!",
                VerificationResult::Invalid => "Invalid message!",
            }
        }

        // Handle a valid signature.
        let verified = pub_a.verify(&msg, &sig_msg);
        assert_eq!("Valid message!", handle_signature_verification(&verified));

        // Let's try an invalid signature
        let new_rand = PrivateKey::random();
        let bad_msg = G2Affine::from(G2Affine::generator() * &new_rand.0);
        let not_verified = pub_a.verify(&bad_msg, &sig_msg);
        assert_eq!(
            "Invalid message!",
            handle_signature_verification(&not_verified)
        );
    }
}
