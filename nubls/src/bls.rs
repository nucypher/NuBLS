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

    pub fn is_fragment(&self) -> PyResult<bool> {
        Ok(self.inner.is_fragment())
    }

    #[classmethod]
    pub fn from_bytes(_cls: &PyType, bytes: &PyBytes) -> PyResult<Signature> {
        Ok(Signature {
            inner: SignatureStub::from_bytes(&bytes.as_bytes()[..]),
        })
    }

    pub fn to_bytes<'p>(&self, py: Python<'p>) -> PyResult<&'p PyBytes> {
        if !self.inner.is_fragment() {
            let mut buff = [0u8; 96];
            self.inner.to_bytes(&mut buff);
            Ok(&PyBytes::new(py, &buff))
        } else {
            let mut buff = [0u8; 128];
            self.inner.to_bytes(&mut buff);
            Ok(&PyBytes::new(py, &buff))
        }
    }
}
