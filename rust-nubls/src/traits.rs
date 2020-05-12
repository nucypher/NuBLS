/// A trait that describes a key that can be used for threshold cryptography
/// protocols. The key that has this trait implemented on it can be split into
/// `n` fragments where `m` fragments (the threshold) must be recovered to
/// re-assemble the full key.
///
/// This is done by implementing a secret sharing scheme such as Shamir's Secret Sharing.
pub trait ThresholdKey: Sized {
    /// The `split` method splits the Threshold key into `n` fragments with
    /// a threshold of `m` fragments required to re-assemble the full key.
    ///
    /// Returns the `n` fragments in a `Vec`.
    fn split(&self, m: usize, n: usize) -> Vec<Self>;

    /// The `recover` function returns the re-assembled key given the threshold
    /// `m` fragments.
    fn recover(fragments: &Vec<Self>) -> Self;
}

/// A trait that describes a signature from a threshold signing protocol.
/// Given a threshold set of signature fragments, a full signature can be assembled
/// and verified by its corresponding threshold key.
pub trait ThresholdSignature: Sized {
    /// The `assemble` function assembles a signature given a `Vec` containing a
    /// threshold amount of signatures.
    /// The fully-assembled signature can be verified by its corresponding
    /// threshold key.
    fn assemble(fragments: &Vec<Self>) -> Self;
}
