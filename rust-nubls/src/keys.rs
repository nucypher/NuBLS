use bls12_381::{G1Affine, Scalar};

/// A `PublicKey` represents an Affine element of the G_1 group on the BLS12-381 curve.
pub struct PublicKey(G1Affine);

/// A `PrivateKey` represents a Scalar element within the order of the BLS12-381 curve.
pub struct PrivateKey(Scalar);
