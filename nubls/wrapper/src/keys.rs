use bls12_381::G2Affine;
use nubls::ThresholdKey;
use nubls::{PrivateKey as PrivateKeyStub, PublicKey as PublicKeyStub};

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};

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
    pub fn sign(&self, message: &PyBytes) -> PyResult<()> {
        let mut msg = [0u8; 96];
        msg.copy_from_slice(message.as_bytes());
        let msg_point = G2Affine::from_compressed(&msg).unwrap();
        let sig = self.inner.sign(&msg_point);
        Ok(())
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
        Ok(PrivateKey { inner: PrivateKeyStub::recover(&f[..]) })
    }
}

#[pymethods]
impl PublicKey {}
