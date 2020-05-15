use crate::bls::{InvalidSignature, Signature};
use bls12_381::G2Affine;
use nubls::ThresholdKey;
use nubls::{PrivateKey as PrivateKeyStub, PublicKey as PublicKeyStub, VerificationResult};

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use pyo3::PyErr;

#[pyclass]
pub struct PublicKey {
    inner: PublicKeyStub,
}

#[pyclass]
pub struct PrivateKey {
    inner: PrivateKeyStub,
}

#[pymethods]
impl PrivateKey {
    #[classmethod]
    pub fn random(_cls: &PyType) -> PyResult<PrivateKey> {
        Ok(PrivateKey {
            inner: PrivateKeyStub::random(),
        })
    }

    pub fn public_key(&self) -> PyResult<PublicKey> {
        Ok(PublicKey {
            inner: self.inner.public_key(),
        })
    }

    // TODO: Finish implementation of `Signature`.
    pub fn sign(&self, message: &PyBytes) -> PyResult<Signature> {
        let mut msg = [0u8; 96];
        msg.copy_from_slice(message.as_bytes());
        Ok(Signature {
            inner: self.inner.sign(&G2Affine::from_compressed(&msg).unwrap()),
        })
    }

    pub fn split(&self, m: usize, n: usize) -> PyResult<Vec<PrivateKey>> {
        Ok(self
            .inner
            .split(m, n)
            .into_iter()
            .map(|fragment| PrivateKey { inner: fragment })
            .collect())
    }

    #[classmethod]
    pub fn recover(_cls: &PyType, fragments: Vec<PyRef<PrivateKey>>) -> PyResult<PrivateKey> {
        let f: Vec<PrivateKeyStub> = fragments
            .into_iter()
            .map(|fragment| fragment.inner)
            .collect();
        Ok(PrivateKey {
            inner: PrivateKeyStub::recover(&f[..]),
        })
    }
}

#[pymethods]
impl PublicKey {
    pub fn verify(&self, message: &PyBytes, signature: &Signature) -> PyResult<bool> {
        let mut msg = [0u8; 96];
        msg.copy_from_slice(message.as_bytes());

        match self
            .inner
            .verify(&G2Affine::from_compressed(&msg).unwrap(), &signature.inner)
        {
            VerificationResult::Valid => Ok(true),
            VerificationResult::Invalid => {
                Err(PyErr::new::<InvalidSignature, _>("Signature is not valid!"))
            }
        }
    }
}
