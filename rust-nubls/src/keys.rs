use crate::bls::{Signature, VerificationResult};
use crate::traits::ThresholdKey;
use crate::utils::{lambda_coeff, poly_eval};

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

    /// Returns the corresponding `PublicKey` of the `PrivateKey`.
    pub fn public_key(&self) -> PublicKey {
        // The BLS12_381 API doesn't work with additive notation, apparently.
        PublicKey((&G1Affine::generator() * &self.0).into())
    }

    /// Signs a `message_element` and returns a `Signature`.
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

/// Allows the ability to use `std::convert::From` to get a `PublicKey` from the
/// corresponding `PrivateKey`.
impl From<PrivateKey> for PublicKey {
    fn from(priv_key: PrivateKey) -> Self {
        priv_key.public_key()
    }
}

/// Implements Shamir's Secret Sharing (SSS) on `PrivateKey` for use in Threshold
/// BLS Signatures.
///
/// SSS has the property of "perfect secrecy" which means that an attacker who
/// holds `m-1` shares of a split key knows nothing; as much info as an attacker
/// who holds none of the shares. These fragments are used as separate, independent
/// private keys in threshold protocols.
impl ThresholdKey for PrivateKey {
    /// Splits the private key into `n` fragments and returns them in a `Vec`
    /// by using Shamir's Secret Sharing.
    ///
    /// The `m` value is the threshold number of fragments required to
    /// re-assemble a secret. An attacker who knows `m-1` fragments knows just
    /// as much as an attacker who holds no shares due to the "perfect secrecy"
    /// of Shamir's Secret Sharing.
    fn split(&self, m: usize, n: usize) -> Vec<PrivateKey> {
        // First, we randomly generate `m-1` coefficients to the polynomial.
        // Our secret is placed as the first term in the polynomial.
        let mut coeffs = Vec::<Scalar>::with_capacity(m);
        coeffs.push(self.0);
        for _ in 1..m {
            coeffs.push(PrivateKey::random().0);
        }

        // Then we evaluate the polynomial `n` times using Horner's method and
        // return the `collect`ed `Vector`.
        // We calculate the fragment index by simply incrementing a Scalar
        // starting at zero. This can be significantly improved, for more info
        // see https://github.com/nucypher/NuBLS/issues/3.
        let mut fragment_index = Scalar::one();
        (0..n)
            .into_iter()
            .map(|_| {
                fragment_index += Scalar::one();
                return PrivateKey(poly_eval(&coeffs[..], &fragment_index));
            })
            .collect()
    }

    /// Recovers a `PrivateKey` from the `fragments` provided by calculating
    /// Lagrange basis polynomials.
    ///
    /// The `fragments` vector must contain the threshold amount (specified as `m`
    /// in the `split` method) to successfully recover the key. Due to the
    /// "perfect secrecy" of Shamir's Secret Sharing, if `fragments` does not
    /// contain the threshold number of fragments (or the wrong fragments), then
    /// this will incorrectly recover the `PrivateKey` without warning.
    fn recover(fragments: &[PrivateKey]) -> PrivateKey {
        // First, we generate the fragment indices.
        // This is done by simply incrementing a Scalar starting from one.
        // This can be significantly improved, for more info see
        // https://github.com/nucypher/NuBLS/issues/3.
        let mut index = Scalar::one();
        let mut fragment_indices = Vec::<Scalar>::with_capacity(fragments.len());
        for _ in 0..fragments.len() {
            fragment_indices.push(index);
            index += Scalar::one();
        }

        // Then we evaluate the Lagrange basis polynomials and return the 
        // recovered `PrivateKey`.
        let mut result = Scalar::zero();
        for (fragment, fragment_index) in fragments.iter().zip(fragment_indices.iter()) {
            result += lambda_coeff(fragment_index, &fragment_indices[..]) * fragment.0;
        }
        PrivateKey(result)
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

    #[test]
    fn test_key_split() {
        let priv_a = PrivateKey::random();
        let n_frags = priv_a.split(2, 3);
        let m_frags = &n_frags[0..1];

        let recovered_a = PrivateKey::recover(&m_frags);
        assert_eq!(recovered_a.0, priv_a.0);
    }
}
