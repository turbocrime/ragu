//! The poly-query commitment scheme: Pedersen-commit a polynomial on the host
//! curve and bridge the resulting point onto the nested curve so it can be
//! witnessed in-circuit.

use alloc::vec;

use ragu_arithmetic::{CurveAffine, Cycle};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Error, Result};

/// Encodes a host-curve point as a nested-curve commitment via the standard
/// bridge encoding: the point's affine coordinates (two `ScalarField`
/// elements) become the coefficients of a two-term polynomial committed on the
/// nested curve. Mirrors the bridge stages (e.g. `nested::stages::f`), which
/// witness a host point as two scalar-field wires of a nested rx polynomial.
///
/// The bridge commitment is unblinded: it binds the host point
/// deterministically. Hiding (a blinded bridge, coordinated with the nested
/// stage masks) is future work.
///
/// # Errors
///
/// Returns [`Error::InvalidWitness`] if `host` is the identity, which has no
/// affine coordinates (and could not be witnessed as a `Point` in-circuit).
pub(crate) fn bridge_commitment<C: Cycle, R: Rank>(
    params: &C::Params,
    host: C::HostCurve,
) -> Result<C::NestedCurve> {
    let coordinates = host.coordinates().into_option().ok_or_else(|| {
        Error::InvalidWitness("identity commitment cannot be bridged to the nested curve".into())
    })?;
    let bridge = sparse::Polynomial::<C::ScalarField, R>::from_coeffs(vec![
        *coordinates.x(),
        *coordinates.y(),
    ]);
    Ok(bridge.commit_to_affine::<C::NestedCurve>(C::nested_generators(params)))
}

/// Commits to a `CircuitField` polynomial in the framework's poly-query
/// commitment scheme: an (unblinded) Pedersen commitment on the host curve,
/// carried onto the nested curve via [`bridge_commitment`] so the result can
/// be witnessed and manipulated in-circuit.
///
/// This is the commitment that
/// [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) claims are
/// checked against at fuse time. Exposed to applications as
/// [`Application::commit_polynomial`](crate::Application::commit_polynomial).
///
/// # Errors
///
/// Returns [`Error::InvalidWitness`] if the polynomial's host commitment is
/// the identity (e.g. the zero polynomial).
pub(crate) fn commit_polynomial<C: Cycle, R: Rank>(
    params: &C::Params,
    polynomial: &sparse::Polynomial<C::CircuitField, R>,
) -> Result<C::NestedCurve> {
    Ok(commit_polynomial_full::<C, R>(params, polynomial)?.1)
}

/// Like [`commit_polynomial`], but also returns the intermediate host-curve
/// commitment, which the fuse pipeline needs for the PCS accumulation (the
/// host point enters the endoscaling points list at the next fuse).
pub(crate) fn commit_polynomial_full<C: Cycle, R: Rank>(
    params: &C::Params,
    polynomial: &sparse::Polynomial<C::CircuitField, R>,
) -> Result<(C::HostCurve, C::NestedCurve)> {
    let host = polynomial.commit_to_affine::<C::HostCurve>(C::host_generators(params));
    Ok((host, bridge_commitment::<C, R>(params, host)?))
}

/// The canonical padding claim used to fill unused poly-query slots (see
/// [`NUM_POLY_QUERY_SLOTS`](crate::NUM_POLY_QUERY_SLOTS)): the constant
/// polynomial $1$, opened at $x = 0$ to $y = 1$, with its (never-identity)
/// host commitment and nested bridge commitment.
pub(crate) struct PaddingClaim<C: Cycle, R: Rank> {
    pub poly: sparse::Polynomial<C::CircuitField, R>,
    pub host: C::HostCurve,
    pub com: C::NestedCurve,
    pub x: C::CircuitField,
    pub y: C::CircuitField,
}

impl<C: Cycle, R: Rank> PaddingClaim<C, R> {
    pub fn new(params: &C::Params) -> Result<Self> {
        use ragu_arithmetic::ff::Field;
        let poly =
            sparse::Polynomial::<C::CircuitField, R>::from_coeffs(vec![C::CircuitField::ONE]);
        let host = poly.commit_to_affine::<C::HostCurve>(C::host_generators(params));
        let com = bridge_commitment::<C, R>(params, host)?;
        Ok(PaddingClaim {
            poly,
            host,
            com,
            x: C::CircuitField::ZERO,
            y: C::CircuitField::ONE,
        })
    }
}
