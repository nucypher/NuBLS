use nubls::Signature as SignatureStub;
use nubls::ThresholdSignature;

use pyo3::prelude::*;
use pyo3::types::PyType;

#[pyclass]
pub struct Signature {
    inner: SignatureStub,
}

#[pymethods]
impl Signature {
    #[classmethod]
    pub fn assemble(_cls: &PyType, fragments: Vec<PyRef<Signature>>) -> PyResult<Signature> {
        let f: Vec<SignatureStub> = fragments
            .into_iter()
            .map(|fragment| fragment.inner)
            .collect();
        Ok(Signature { inner: SignatureStub::assemble(&f[..]) })
    }
}
