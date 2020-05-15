use nubls::{Signature as SignatureStub, ThresholdSignature};

use pyo3::create_exception;
use pyo3::exceptions::Exception;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};

create_exception!(nubls_wrapper, InvalidSignature, Exception);

#[pyclass]
pub struct Signature {
    pub(crate) inner: SignatureStub,
}

#[pymethods]
impl Signature {
    #[classmethod]
    pub fn assemble(_cls: &PyType, fragments: Vec<PyRef<Signature>>) -> PyResult<Signature> {
        let f: Vec<SignatureStub> = fragments
            .into_iter()
            .map(|fragment| fragment.inner)
            .collect();
        Ok(Signature {
            inner: SignatureStub::assemble(&f[..]),
        })
    }

    #[classmethod]
    pub fn from_bytes(_cls: &PyType, bytes: &PyBytes) -> PyResult<Signature> {
        let mut sig = [0u8; 96];
        sig.copy_from_slice(bytes.as_bytes());
        Ok(Signature {
            inner: SignatureStub::from_bytes(&sig),
        })
    }

    pub fn to_bytes<'p>(&self, py: Python<'p>) -> PyResult<&'p PyBytes> {
        Ok(&PyBytes::new(py, &self.inner.to_bytes()[..]))
    }
}
