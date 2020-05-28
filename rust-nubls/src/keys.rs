use crate::bls::{Signature, VerificationResult};
use crate::traits::{PRSKey, ThresholdKey};
use crate::utils::{lambda_coeff, poly_eval};

use bls12_381::{G1Affine, G2Affine, Scalar};
use getrandom;

use sha2::{Digest, Sha512};

pub(crate) const SCALAR_BYTES_LENGTH: usize = 32;

/// A `PublicKey` represents an Affine element of the G_1 group on the BLS12-381 curve.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct PublicKey(pub(crate) G1Affine);

/// A `PrivateKey` represents a Scalar element within the order of the BLS12-381 curve.
/// We have an `Option<Scalar>` field for a Fragment ID in the case of Threshold signatures.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct PrivateKey(pub(crate) Scalar, pub(crate) Option<Scalar>);

impl PrivateKey {
    /// Generates a random private key and returns it.
    pub fn random() -> PrivateKey {
        let mut key_bytes = [0u8; 64];
        match getrandom::getrandom(&mut key_bytes) {
            Ok(_) => return PrivateKey(Scalar::from_bytes_wide(&key_bytes), None),
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

    /// Serializes the `PrivateKey` by filling a buffer passed as an argument.
    /// If the buffer is not big enough, this method will panic.
    ///
    /// A `PrivateKey` can be serialized in two ways:
    ///  1. 32 bytes -- This is the case when a `PrivateKey` is _not_ being
    ///  used for a threshold signature.
    ///
    ///  2. 64 bytes -- This is the case when a `PrivateKey` _is_ being used
    ///  for a threshold signature. This allows us to store its fragment
    ///  ID for Shamir's Secret Sharing.
    ///
    /// Note: This serialization will probably change in the future.
    /// See https://github.com/nucypher/NuBLS/issues/3
    pub fn to_bytes(&self, buff: &mut [u8]) {
        buff[0..32].copy_from_slice(&self.0.to_bytes()[..]);
        if let Some(fragment_index) = self.1 {
            buff[32..64].copy_from_slice(&fragment_index.to_bytes()[..]);
        }
    }

    /// Deserializes from a `&[u8]` to a `PrivateKey`.
    /// This will panic if the input is not canonical.
    ///
    /// A `PrivateKey` can be serialized in two ways:
    ///  1. 32 bytes -- This is the case when a `PrivateKey` is _not_ being
    ///  used for a threshold signature.
    ///
    ///  2. 64 bytes -- This is the case when a `PrivateKey` _is_ being used
    ///  for a threshold signature. This allows us to store its fragment
    ///  ID for Shamir's Secret Sharing.
    ///
    /// Note: This serialization will probably change in the future.
    /// See https://github.com/nucypher/NuBLS/issues/3
    pub fn from_bytes(bytes: &[u8]) -> PrivateKey {
        let mut scalar_bytes = [0u8; 32];
        let fragment_index: Option<Scalar>;
        if bytes.len() == SCALAR_BYTES_LENGTH {
            scalar_bytes.copy_from_slice(&bytes);
            fragment_index = None;
        } else {
            let mut index_bytes = [0u8; 32];
            scalar_bytes.copy_from_slice(&bytes[0..SCALAR_BYTES_LENGTH]);
            index_bytes.copy_from_slice(&bytes[SCALAR_BYTES_LENGTH..64]);
            fragment_index = Some(Scalar::from_bytes(&index_bytes).unwrap());
        }
        PrivateKey(Scalar::from_bytes(&scalar_bytes).unwrap(), fragment_index)
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

    /// Serializes the `PublicKey` to an array of 48 bytes.
    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_compressed()
    }

    /// Deserializes from a `&[u8; 48]` to a `PublicKey`.
    /// This will panic if the input is not valid.
    pub fn from_bytes(bytes: &[u8; 48]) -> PublicKey {
        PublicKey(G1Affine::from_compressed(bytes).unwrap())
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
        // The index can be significantly improved, for more info see
        // https://github.com/nucypher/NuBLS/issues/3.
        let mut fragments = Vec::<PrivateKey>::with_capacity(n);
        for _ in 0..n {
            let fragment_index = PrivateKey::random().0;
            fragments.push(PrivateKey(
                poly_eval(&coeffs[..], &fragment_index),
                Some(fragment_index),
            ));
        }
        fragments
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
        // We create a buffer to hold fragment indices of size 256 because
        // our limit to fragments is 256.
        // This can be significantly improved, for more info see
        // https://github.com/nucypher/NuBLS/issues/3.
        // TODO: https://github.com/nucypher/NuBLS/issues/25
        let mut fragment_indices = [Scalar::zero(); 256];
        for i in 0..fragments.len() {
            fragment_indices[i] = fragments[i].1.unwrap();
        }

        // Then we evaluate the Lagrange basis polynomials and return the
        // recovered `PrivateKey`.
        // Note: we limit the `fragments_indices` slice to the length of the
        // `fragments` slice.
        let mut result = Scalar::zero();
        for fragment in fragments.iter() {
            result += lambda_coeff(&fragment.1.unwrap(), &fragment_indices[..fragments.len()])
                * fragment.0;
        }
        PrivateKey(result, None)
    }

    /// Returns whether or not this is a fragment of a key used for 
    /// threshold signatures.
    fn is_fragment(&self) -> bool {
        match self.1 {
            Some(_) => true,
            None => false,
        }
    }
}

impl PRSKey for PrivateKey {
    /// Calculates $\phi_{B \rightarrow A}$ as $\frac{a}{\phi_B}$
    fn resigning_key(&self, bob_pubkey: &PublicKey) -> PrivateKey {
        let phi_b = self.designated_key(&bob_pubkey).0;
        PrivateKey(self.0 * (phi_b.invert().unwrap()), None)
    }

    /// Calculate $\phi_B$ as a Diffie-Hellman between Alice and Bob.
    fn designated_key(&self, alice_pubkey: &PublicKey) -> PrivateKey {
        let dh = Sha512::digest(&G1Affine::from(alice_pubkey.0 * &self.0).to_uncompressed());
        let mut scalar_bytes = [0u8; 64];
        scalar_bytes.copy_from_slice(&dh.as_slice());
        PrivateKey(Scalar::from_bytes_wide(&scalar_bytes), None)
    }

    /// Re-Signs a `Signature` from $\sigma_{\phi_B}$ to $\sigma_A$.
    /// This is done by multiplying the `Signature` by the re-signing key:
    /// $\sigma_A = \phi_{B \rightarrow A} \cdot \sigma_{\phi_B}$
    fn resign(&self, signature: &Signature) -> Signature {
        Signature::new(&self, &signature.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ThresholdSignature;

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

        // Generate and sign a random message in G_2.
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
    fn test_key_split_3_of_5() {
        let priv_a = PrivateKey::random();
        let n_frags = priv_a.split(3, 5);
        let m_frags = &n_frags[0..3];

        let recovered_a = PrivateKey::recover(&m_frags);
        assert_eq!(recovered_a, priv_a);
    }

    #[test]
    fn test_key_serialization() {
        let priv_a = PrivateKey::random();
        let n_frags = priv_a.split(3, 5);

        let mut a_bytes = [0u8; 32];
        let mut frag_bytes = [0u8; 64];
        priv_a.to_bytes(&mut a_bytes);
        n_frags[0].to_bytes(&mut frag_bytes);

        assert_eq!(a_bytes.len(), 32);
        assert_eq!(frag_bytes.len(), 64);
        assert_ne!(a_bytes[..32], frag_bytes[..32]);

        assert_eq!(PrivateKey::from_bytes(&a_bytes), priv_a);
        assert_eq!(PrivateKey::from_bytes(&frag_bytes), n_frags[0]);
    }

    #[test]
    fn test_signature_serialization() {
        let priv_a = PrivateKey::random();
        let n_frags = priv_a.split(3, 5);

        let rand = PrivateKey::random();
        let msg = G2Affine::from(G2Affine::generator() * &rand.0);
        let sig = priv_a.sign(&msg);
        let frag_sig = n_frags[0].sign(&msg);

        let mut sig_bytes = [0u8; 96];
        let mut frag_sig_bytes = [0u8; 128];
        sig.to_bytes(&mut sig_bytes);
        frag_sig.to_bytes(&mut frag_sig_bytes);

        assert_eq!(sig_bytes.len(), 96);
        assert_eq!(frag_sig_bytes.len(), 128);
        assert_ne!(sig_bytes[..96], frag_sig_bytes[..96]);

        assert_eq!(Signature::from_bytes(&sig_bytes), sig);
        assert_eq!(Signature::from_bytes(&frag_sig_bytes), frag_sig);
    }

    #[test]
    fn test_is_fragment() {
        // Testing `PrivateKey`
        let priv_a = PrivateKey::random();
        let n_frags = priv_a.split(3, 5);
        assert_eq!(n_frags[0].is_fragment(), true);
        assert_eq!(priv_a.is_fragment(), false);

        // Testing `Signature`
        let rand = PrivateKey::random();
        let msg = G2Affine::from(G2Affine::generator() * &rand.0);
        let sig = n_frags[0].sign(&msg);
        assert_eq!(sig.is_fragment(), true);
        assert_eq!(priv_a.sign(&msg).is_fragment(), false);
    }

    #[test]
    fn test_incomplete_key_recovery() {
        let priv_a = PrivateKey::random();
        let n_frags = priv_a.split(3, 5);

        // Select m fragments under the threshold and attempt recovery
        let m_frags = &n_frags[0..2];
        let bad_recovery = PrivateKey::recover(&m_frags);
        assert_ne!(bad_recovery, priv_a);
    }

    #[test]
    fn test_threshold_signature_3_of_5() {
        // Split the private key into five fragments, one for each Signer.
        let priv_a = PrivateKey::random();
        let n_frags = priv_a.split(3, 5);

        // Generate a random message in G_2
        let rand = PrivateKey::random();
        let msg = G2Affine::from(G2Affine::generator() * &rand.0);

        // Get three signatures on the `msg` from each Signer
        let sig_1 = n_frags[0].sign(&msg);
        let sig_2 = n_frags[1].sign(&msg);
        let sig_3 = n_frags[3].sign(&msg);

        // Place them into a vector and assemble the full signature
        let sig_frags = vec![sig_1, sig_2, sig_3];
        let full_sig = Signature::assemble(&sig_frags[..]);

        // Sign the same data with the unsplit key to verify correctness
        // BLS is a deterministic signature, so we can simply check that the
        // two signatures are identical.
        let msg_sig = priv_a.sign(&msg);
        assert_eq!(msg_sig, full_sig);

        // Check that the signature verifies
        let pub_a = priv_a.public_key();
        assert_eq!(pub_a.verify(&msg, &full_sig), VerificationResult::Valid);
    }

    #[test]
    fn test_unordered_index_key_recovery() {
        let priv_a = PrivateKey::random();
        let n_frags = priv_a.split(3, 5);
        let m_frags = &n_frags[2..5];

        let recovered_a = PrivateKey::recover(&m_frags);
        assert_eq!(recovered_a, priv_a);
    }

    #[test]
    fn test_unordered_index_signature_assembly() {
        let priv_a = PrivateKey::random();
        let n_frags = priv_a.split(3, 5);

        let rand = PrivateKey::random();
        let msg = G2Affine::from(G2Affine::generator() * &rand.0);

        let sig_1 = n_frags[0].sign(&msg);
        let sig_2 = n_frags[1].sign(&msg);
        let sig_3 = n_frags[3].sign(&msg);

        let sig_frags = vec![sig_1, sig_2, sig_3];
        let full_sig = Signature::assemble(&sig_frags[..]);

        // Check that the signature verifies
        let pub_a = priv_a.public_key();
        assert_eq!(pub_a.verify(&msg, &full_sig), VerificationResult::Valid);
    }

    #[test]
    fn test_incomplete_signature_assembly() {
        // Split the private key into five fragments, one for each Signer.
        let priv_a = PrivateKey::random();
        let n_frags = priv_a.split(3, 5);

        // Generate a random message in G_2
        let rand = PrivateKey::random();
        let msg = G2Affine::from(G2Affine::generator() * &rand.0);

        // Get two signatures on the `msg`; under the threshold
        let sig_1 = n_frags[0].sign(&msg);
        let sig_2 = n_frags[1].sign(&msg);

        // Place them into a vector and assemble an incomplete signature
        let sig_frags = vec![sig_1, sig_2];
        let bad_sig = Signature::assemble(&sig_frags[..]);

        // Sign the same data with the unsplit key to verify correctness
        // BLS is a deterministic signature, so we can simply check that the
        // two signatures are identical.
        let msg_sig = priv_a.sign(&msg);
        assert_ne!(msg_sig, bad_sig);
    }

    #[test]
    fn test_proxy_re_signature() {
        let priv_alice = PrivateKey::random();
        let pub_alice = priv_alice.public_key();

        let priv_bob = PrivateKey::random();
        let pub_bob = priv_bob.public_key();

        // Generate a random message in G_2 to sign
        let rand = PrivateKey::random();
        let msg = G2Affine::from(G2Affine::generator() * &rand.0);

        // Alice grants re-signing capabilities to Bob by generating a
        // resigning key that transforms signatures from Bob's designated key
        // to Alice's key.
        let rekey_ab = priv_alice.resigning_key(&pub_bob);

        // Bob now signs with his designated key for Alice.
        // Note: this is not a signature under Bob's key. It's a signature
        // under a "designated key" that is specific for re-signing to Alice.
        let sig_b = priv_bob.designated_key(&pub_alice).sign(&msg);
        assert_ne!(sig_b, priv_bob.sign(&msg));
        assert_eq!(pub_bob.verify(&msg, &sig_b), VerificationResult::Invalid);

        // We re-sign the signature to Alice's key with the re-signing key.
        // Note: this is the exact same signature that Alice would create
        // had she made the signature herself.
        let sig_a = rekey_ab.resign(&sig_b);
        assert_eq!(sig_a, priv_alice.sign(&msg));
        assert_eq!(pub_alice.verify(&msg, &sig_a), VerificationResult::Valid);
    }
}
