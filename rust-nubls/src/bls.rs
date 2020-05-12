use bls12_381::G2Affine;

/// A `Signature` is an Affine element of the G_2 group on the BLS12-381 curve.
pub struct Signature(G2Affine);
