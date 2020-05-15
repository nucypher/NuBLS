extern crate nubls;

use pyo3::prelude::*;

pub mod bls;
pub mod keys;

#[pymodule]
fn nubls(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<keys::PrivateKey>()?;
    m.add_class::<keys::PublicKey>()?;
    m.add_class::<bls::Signature>()?;
    Ok(())
}
