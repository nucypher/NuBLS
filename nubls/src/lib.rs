extern crate nubls;

use crate::bls::InvalidSignature;
use pyo3::prelude::*;

pub mod bls;
pub mod keys;

#[pymodule]
fn nubls_wrapper(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<keys::PrivateKey>()?;
    m.add_class::<keys::PublicKey>()?;
    m.add_class::<bls::Signature>()?;
    m.add("InvalidSignature", py.get_type::<InvalidSignature>())?;
    Ok(())
}
