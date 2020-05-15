use nubls::Signature as SignatureStub;
use nubls::ThresholdSignature;

use pyo3::create_exception;
use pyo3::exceptions::Exception;
use pyo3::prelude::*;
use pyo3::types::PyType;

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
}
