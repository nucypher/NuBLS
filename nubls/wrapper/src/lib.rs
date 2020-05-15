extern crate nubls;

use pyo3::prelude::*;

pub mod keys;
pub mod bls;

#[pymodule]
fn nubls_wrapper(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<keys::PrivateKey>()?;
    m.add_class::<keys::PublicKey>()?;
    m.add_class::<bls::Signature>()?;
    Ok(())
}
