extern crate nubls;

use pyo3::prelude::*;

pub mod keys;

#[pymodule]
fn nubls_wrapper(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<keys::PrivateKey>()?;
    m.add_class::<keys::PublicKey>()?;
    Ok(())
}
