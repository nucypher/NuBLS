use bls12_381::{pairing, G1Affine, G2Affine, G2Projective, Scalar};

use crate::keys::{PrivateKey, PublicKey};
use crate::traits::ThresholdSignature;
use crate::utils::lambda_coeff;

const G2_POINT_BYTES_LENGTH: usize = 96;

/// This type represents the output of a Signature verification.
///
/// By representing signature verification in an `enum` like this, we are able
/// to construct a safe, misuse resistant API by forcing the user to handle
/// both cases of signature verification logic (Valid/Invalid). This prevents
/// silent failures that otherwise may be present when APIs return `bool`s.
#[derive(Debug, Eq, PartialEq)]
pub enum VerificationResult {
    Valid,
    Invalid,
}

/// A `Signature` is an Affine element of the G_2 group on the BLS12-381 curve.
/// We have an `Option<Scalar>` field for a Fragment ID in the case of Threshold signatures.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct Signature(pub(crate) G2Affine, Option<Scalar>);

impl Signature {
    /// Creates a `Signature` and returns it by signing the `message_element`
    /// with the provided `private_key`.
    ///
    /// The preferred API to sign messages is in `PrivateKey.sign`.
    ///
    /// Presently, the API for hashing to the G_2 group of BLS12-381 is not
    /// implemented (see https://github.com/nucypher/NuBLS/issues/1). Therefore,
    /// the message must be prehashed before verification and signing.
    ///
    /// TODO: Implement hash_to_curve
    pub(crate) fn new(private_key: &PrivateKey, message_element: &G2Affine) -> Signature {
        Signature((message_element * &private_key.0).into(), private_key.1)
    }

    /// Attempts to verify the signature given a `message_element` and a `public_key`.
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
        let c_1 = pairing(&public_key.0, &message_element);
        let c_2 = pairing(&G1Affine::generator(), &self.0);

        VerificationResult::from(c_1 == c_2)
    }

    /// Serializes the `Signature` by filling a buffer passed as an argument.
    /// If the buffer is not big enough, this method will panic.
    ///
    /// A `Signature` can be serialized in two ways:
    ///  1. 96 bytes -- This is the case when a `Signature` is _not_ a fragment
    ///  to a threshold signature.
    ///
    ///  2. 128 bytes -- This is the case when a `Signature` _is_ a fragment
    ///  to a threshold signature. This allows us to store its fragment ID for
    ///  Shamir's Secret Sharing.
    ///
    ///  Note: This serialization will probably change in the future.
    ///  See https://github.com/nucypher/NuBLS/issues/3
    pub fn to_bytes(&self, buff: &mut [u8]) {
        buff[0..96].copy_from_slice(&self.0.to_compressed()[..]);
        if let Some(fragment_index) = self.1 {
            buff[96..128].copy_from_slice(&fragment_index.to_bytes()[..]);
        }
    }

    /// Deserializes from a `&[u8; 96]` to a `Signature`.
    /// This will panic if the input is not canonical.
    ///
    /// A `Signature` can be serialized in two ways:
    ///  1. 96 bytes -- This is the case when a `Signature` is _not_ a fragment
    ///  to a threshold signature.
    ///
    ///  2. 128 bytes -- This is the case when a `Signature` _is_ a fragment
    ///  to a threshold signature. This allows us to store its fragment ID for
    ///  Shamir's Secret Sharing.
    ///
    ///  Note: This serialization will probably change in the future.
    ///  See https://github.com/nucypher/NuBLS/issues/3
    pub fn from_bytes(bytes: &[u8]) -> Signature {
        let mut point_bytes = [0u8; 96];
        let fragment_index: Option<Scalar>;
        if bytes.len() == G2_POINT_BYTES_LENGTH {
            point_bytes.copy_from_slice(&bytes);
            fragment_index = None
        } else {
            let mut index_bytes = [0u8; 32];
            point_bytes.copy_from_slice(&bytes[0..G2_POINT_BYTES_LENGTH]);
            index_bytes.copy_from_slice(&bytes[G2_POINT_BYTES_LENGTH..128]);
            fragment_index = Some(Scalar::from_bytes(&index_bytes).unwrap());
        }
        Signature(
            G2Affine::from_compressed(&point_bytes).unwrap(),
            fragment_index,
        )
    }
}

/// Implements Threshold BLS signatures on `Signature`.
///
/// We use Shamir's Secret Sharing scheme to share `n` fragments of a `PrivateKey`
/// where `m` fragments are needed to recover it.
/// For BLS threshold signatures, this translates to needing `m` signatures of
/// identical data to assemble the final `Signature`.
impl ThresholdSignature for Signature {
    /// Assembles a `Signature` from collected signature `fragments`.
    ///
    /// Note: The data signed by each of the fragment signatures must be identical,
    /// or else the assembled `Signature` will be invalid.
    ///
    /// This calculates the final signature by using Lagrange basis polynomials.
    fn assemble(fragments: &[Signature]) -> Signature {
        // First, we generate the fragment indices.
        // We create a buffer to hold fragment indices of size 256 because
        // our limit to fragments is 256.
        // This can be significantly improved, for more info see
        // https://github.com/nucypher/NuBLS/issues/3.
        let mut fragment_indices = [Scalar::zero(); 256];
        for i in 0..fragments.len() {
            fragment_indices[i] = fragments[i].1.unwrap();
        }

        // Then we evaluate the lagrange basis polynomials and assemble the
        // full `Signature`.
        // Note: we limit the `fragments_indices` slice to the length of the 
        // `fragments` slice.
        let mut result = G2Projective::identity();
        for fragment in fragments.iter() {
            // The BLS12_381 API doesn't use additive notation, apparently.
            result +=
                fragment.0 * lambda_coeff(&fragment.1.unwrap(), &fragment_indices[..fragments.len()]);
        }
        Signature(result.into(), None)
    }

    /// Returns whether or not this is a fragment of a threshold signature.
    fn is_fragment(&self) -> bool {
        match self.1 {
            Some(_) => true,
            None => false,
        }
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
