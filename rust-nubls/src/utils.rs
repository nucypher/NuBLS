use bls12_381::Scalar;

/// Evaluates a polynomial using Horner's method.
///
/// `poly_coeffs` is a slice containing the coefficients in the polynomial
/// and `x` is the value to evaluate with.
///
/// Horner's method allows us to efficiently evaluate polynomials with `n`
/// additions and multiplications. It leverages the identity:
/// p(x) = a_0 + a_1x + a_2x^2 + ... + a_{n}x^n
///      = a_0 + x(a_1 + x(a_2 + ... + x(a_{n-1} + x(a_n))))
///
/// TODO: Does this need error handling properly?
pub(crate) fn poly_eval(poly_coeffs: &[Scalar], x: &Scalar) -> Scalar {
    let mut result: Scalar;
    if let Some((leading_coeff, coeffs)) = poly_coeffs.split_last() {
        result = *leading_coeff;
        for coeff in coeffs.iter().rev() {
            result = (result * x) + coeff;
        }
    } else {
        panic!("Tried to evaluate a polynomial with no coefficients.")
    }
    result
}

pub(crate) fn lambda_coeff(fragment_index: &Scalar, fragment_indices: &[Scalar]) -> Scalar {
    let mut result: Scalar;
    if let Some((x_0, xs)) = fragment_indices.split_first() {
        result = *x_0 * (*x_0 - fragment_index).invert().unwrap();
        for x_m in xs.iter().filter(|&x| *x != *fragment_index) {
            result *= x_m * (x_m - fragment_index).invert().unwrap();
        }
    } else {
        // Returns `one` when the `fragment_indices` slice is empty.
        return Scalar::one();
    }
    result
}
