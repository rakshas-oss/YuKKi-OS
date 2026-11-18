//! Bounded real-symmetric eigensolver using cyclic Jacobi rotations.
//!
//! Intended for small/medium covariance and correlation matrices (dimension
//! 1..=64). This is a CPU reference implementation shared by native dataset
//! benchmarks and WASM-capable callers. It does not solve general non-symmetric
//! or complex eigenproblems.

use thiserror::Error;

pub const MAX_EIGEN_DIMENSION: usize = 64;
pub const DEFAULT_TOLERANCE: f64 = 1.0e-12;
pub const DEFAULT_MAX_SWEEPS: usize = 128;

/// Standard real arcsecant: acos(1/x), defined only for finite |x| >= 1.\npub fn arcsecant(value: f64) -> Option<f64> {\n    if value.is_finite() && value.abs() >= 1.0 {\n        Some((1.0 / value).clamp(-1.0, 1.0).acos())\n    } else {\n        None\n    }\n}\n
#[derive(Debug, Clone, PartialEq)]
pub struct EigenDecomposition {
    /// Eigenvalues in ascending order.
    pub eigenvalues: Vec<f64>,
    /// Row-major eigenvector matrix; eigenvectors are columns.
    pub eigenvectors: Vec<f64>,
    pub relative_residual: f64,
    pub orthogonality_error: f64,
    pub sweeps: usize,
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum EigenError {
    #[error("matrix dimension must be in 1..={MAX_EIGEN_DIMENSION}")]
    InvalidDimension,
    #[error("matrix storage length does not equal dimension squared")]
    InvalidLength,
    #[error("matrix contains a non-finite value")]
    NonFinite,
    #[error("matrix is not symmetric within the configured tolerance")]
    NotSymmetric,
    #[error("tolerance must be finite and in (0, 1) and max_sweeps must be in 1..=1024")]
    InvalidOptions,
    #[error("Jacobi iteration did not converge within the configured sweep limit")]
    NotConverged,
    #[error("eigenvalue rescaling overflowed")]
    NumericalOverflow,
}

/// Solve A v = lambda v for a finite real-symmetric row-major matrix.
pub fn symmetric_eigen_decomposition(
    matrix: &[f64],
    dimension: usize,
) -> Result<EigenDecomposition, EigenError> {
    symmetric_eigen_decomposition_with_options(
        matrix,
        dimension,
        DEFAULT_TOLERANCE,
        DEFAULT_MAX_SWEEPS,
    )
}

/// Configurable cyclic Jacobi solver. The input is never mutated.
pub fn symmetric_eigen_decomposition_with_options(
    matrix: &[f64],
    dimension: usize,
    tolerance: f64,
    max_sweeps: usize,
) -> Result<EigenDecomposition, EigenError> {
    if dimension == 0 || dimension > MAX_EIGEN_DIMENSION {
        return Err(EigenError::InvalidDimension);
    }
    if matrix.len() != dimension * dimension {
        return Err(EigenError::InvalidLength);
    }
    if !tolerance.is_finite()
        || tolerance <= 0.0
        || tolerance >= 1.0
        || max_sweeps == 0
        || max_sweeps > 1024
    {
        return Err(EigenError::InvalidOptions);
    }
    if matrix.iter().any(|value| !value.is_finite()) {
        return Err(EigenError::NonFinite);
    }

    // Normalize before rotations to avoid overflow in the off-diagonal update.
    let scale = matrix.iter().fold(0.0_f64, |current, value| current.max(value.abs()));
    let divisor = if scale == 0.0 { 1.0 } else { scale };
    let mut a: Vec<f64> = matrix.iter().map(|value| value / divisor).collect();

    for row in 0..dimension {
        for column in (row + 1)..dimension {
            let left = a[row * dimension + column];
            let right = a[column * dimension + row];
            if (left - right).abs() > tolerance * (1.0 + left.abs().max(right.abs())) {
                return Err(EigenError::NotSymmetric);
            }
            let average = 0.5 * (left + right);
            a[row * dimension + column] = average;
            a[column * dimension + row] = average;
        }
    }

    let original = a.clone();
    let mut vectors = vec![0.0; dimension * dimension];
    for index in 0..dimension {
        vectors[index * dimension + index] = 1.0;
    }

    let mut converged = dimension == 1;
    let mut sweeps_used = 0;
    for sweep in 0..max_sweeps {
        let mut max_diagonal = 0.0_f64;
        for index in 0..dimension {
            max_diagonal = max_diagonal.max(a[index * dimension + index].abs());
        }

        for p in 0..dimension {
            for q in (p + 1)..dimension {
                let apq = a[p * dimension + q];
                if apq.abs() <= tolerance * max_diagonal.max(1.0) {
                    continue;
                }

                let app = a[p * dimension + p];
                let aqq = a[q * dimension + q];
                let tau = (aqq - app) / (2.0 * apq);
                let sign = if tau < 0.0 { -1.0 } else { 1.0 };
                let t = sign / (tau.abs() + tau.hypot(1.0));
                let cosine = 1.0 / (1.0 + t * t).sqrt();
                let sine = t * cosine;

                for k in 0..dimension {
                    if k == p || k == q {
                        continue;
                    }
                    let akp = a[k * dimension + p];
                    let akq = a[k * dimension + q];
                    let new_kp = cosine * akp - sine * akq;
                    let new_kq = sine * akp + cosine * akq;
                    a[k * dimension + p] = new_kp;
                    a[p * dimension + k] = new_kp;
                    a[k * dimension + q] = new_kq;
                    a[q * dimension + k] = new_kq;
                }

                a[p * dimension + p] = app - t * apq;
                a[q * dimension + q] = aqq + t * apq;
                a[p * dimension + q] = 0.0;
                a[q * dimension + p] = 0.0;

                for k in 0..dimension {
                    let vkp = vectors[k * dimension + p];
                    let vkq = vectors[k * dimension + q];
                    vectors[k * dimension + p] = cosine * vkp - sine * vkq;
                    vectors[k * dimension + q] = sine * vkp + cosine * vkq;
                }
            }
        }

        sweeps_used = sweep + 1;
        let residual_off_diagonal = (0..dimension)
            .flat_map(|row| ((row + 1)..dimension).map(move |column| (row, column)))
            .map(|(row, column)| a[row * dimension + column].abs())
            .fold(0.0_f64, f64::max);
        let diagonal_scale = (0..dimension)
            .map(|index| a[index * dimension + index].abs())
            .fold(1.0_f64, f64::max);
        if residual_off_diagonal <= tolerance * diagonal_scale {
            converged = true;
            break;
        }
    }
    if !converged {
        return Err(EigenError::NotConverged);
    }

    let mut order: Vec<usize> = (0..dimension).collect();
    order.sort_by(|left, right| {
        a[left * dimension + left].total_cmp(&a[right * dimension + right])
    });
    let eigenvalues: Vec<f64> = order
        .iter()
        .map(|index| a[index * dimension + index] * divisor)
        .collect();
    if eigenvalues.iter().any(|value| !value.is_finite()) {
        return Err(EigenError::NumericalOverflow);
    }

    let mut sorted_vectors = vec![0.0; dimension * dimension];
    for row in 0..dimension {
        for (new_column, old_column) in order.iter().copied().enumerate() {
            sorted_vectors[row * dimension + new_column] =
                vectors[row * dimension + old_column];
        }
    }

    let mut residual_squared = 0.0;
    let mut matrix_norm_squared = 0.0;
    let mut orthogonality_squared = 0.0;
    for row in 0..dimension {
        for column in 0..dimension {
            let mut av = 0.0;
            for k in 0..dimension {
                av += original[row * dimension + k] * sorted_vectors[k * dimension + column];
            }
            let vlambda =
                sorted_vectors[row * dimension + column] * (eigenvalues[column] / divisor);
            let difference = av - vlambda;
            residual_squared += difference * difference;
            matrix_norm_squared += original[row * dimension + column].powi(2);

            let mut dot = 0.0;
            for k in 0..dimension {
                dot += sorted_vectors[k * dimension + row]
                    * sorted_vectors[k * dimension + column];
            }
            let expected = if row == column { 1.0 } else { 0.0 };
            orthogonality_squared += (dot - expected).powi(2);
        }
    }

    Ok(EigenDecomposition {
        eigenvalues,
        eigenvectors: sorted_vectors,
        relative_residual: residual_squared.sqrt() / matrix_norm_squared.sqrt().max(1.0),
        orthogonality_error: orthogonality_squared.sqrt(),
        sweeps: sweeps_used,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagonal_matrix_returns_sorted_eigenvalues_and_basis() {
        let result = symmetric_eigen_decomposition(&[4.0, 0.0, 0.0, 0.0, -2.0, 0.0, 0.0, 0.0, 1.0], 3)
            .unwrap();
        assert_eq!(result.eigenvalues, vec![-2.0, 1.0, 4.0]);
        assert!(result.relative_residual < 1.0e-12);
        assert!(result.orthogonality_error < 1.0e-12);
    }

    #[test]
    fn two_by_two_rotation_solves_known_eigenvalues() {
        let result = symmetric_eigen_decomposition(&[2.0, 1.0, 1.0, 2.0], 2).unwrap();
        assert!((result.eigenvalues[0] - 1.0).abs() < 1.0e-12);
        assert!((result.eigenvalues[1] - 3.0).abs() < 1.0e-12);
        assert!(result.relative_residual < 1.0e-12);
        assert!(result.orthogonality_error < 1.0e-12);
    }

    #[test]
    fn positive_definite_three_by_three_has_small_residual() {
        let matrix = [4.0, 1.0, 1.0, 1.0, 3.0, 0.0, 1.0, 0.0, 2.0];
        let result = symmetric_eigen_decomposition(&matrix, 3).unwrap();
        assert!(result.eigenvalues.iter().all(|value| *value > 0.0));
        assert!(result.relative_residual < 1.0e-11);
        assert!(result.orthogonality_error < 1.0e-11);
    }

    #[test]
    fn arcsecant_mapping_respects_its_real_domain() {
        assert!((arcsecant(1.0).unwrap() - 0.0).abs() < 1.0e-15);
        assert!((arcsecant(2.0).unwrap() - (0.5_f64).acos()).abs() < 1.0e-15);
        assert!((arcsecant(-1.0).unwrap() - std::f64::consts::PI).abs() < 1.0e-15);
        assert!(arcsecant(0.5).is_none());
        assert!(arcsecant(f64::NAN).is_none());
    }

    #[test]
    fn rejects_invalid_matrix_shapes_and_values() {
        assert_eq!(
            symmetric_eigen_decomposition(&[], 0),
            Err(EigenError::InvalidDimension)
        );
        assert_eq!(
            symmetric_eigen_decomposition(&[1.0, 2.0], 2),
            Err(EigenError::InvalidLength)
        );
        assert_eq!(
            symmetric_eigen_decomposition(&[1.0, 2.0, 0.0, 1.0], 2),
            Err(EigenError::NotSymmetric)
        );
        assert_eq!(
            symmetric_eigen_decomposition(&[1.0, f64::NAN, f64::NAN, 1.0], 2),
            Err(EigenError::NonFinite)
        );
    }

    #[test]
    fn handles_zero_matrix_and_large_scale_without_losing_eigenvectors() {
        let zero = symmetric_eigen_decomposition(&[0.0; 9], 3).unwrap();
        assert_eq!(zero.eigenvalues, vec![0.0; 3]);
        let huge = symmetric_eigen_decomposition(&[1.0e200, 2.0e199, 2.0e199, 3.0e200], 2).unwrap();
        assert!(huge.eigenvalues.iter().all(|value| value.is_finite()));
        assert!(huge.relative_residual < 1.0e-11);
    }
}
