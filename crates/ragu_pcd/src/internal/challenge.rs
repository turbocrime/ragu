//! The poly-query commitment scheme: Pedersen-commit a polynomial on the host
//! curve and bridge the resulting point onto the nested curve so it can be
//! witnessed in-circuit.

use alloc::vec;

use ragu_arithmetic::{CurveAffine, Cycle};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Error, Result};

/// The host-curve commitment to a poly-query polynomial, rejecting the
/// identity (which has no affine coordinates, so it could not be witnessed as
/// a `Point` nor bridged).
pub(crate) fn host_commitment<C: Cycle, R: Rank>(
    params: &C::Params,
    polynomial: &sparse::Polynomial<C::CircuitField, R>,
) -> Result<C::HostCurve> {
    let host = polynomial.commit_to_affine::<C::HostCurve>(C::host_generators(params));
    if host.coordinates().into_option().is_none() {
        return Err(Error::InvalidWitness(
            "polynomial commitment is the identity and cannot be witnessed in-circuit".into(),
        ));
    }
    Ok(host)
}

/// The stage blind for poly-query claim `slot`, derived from the proof's
/// shared `bridge_alpha` source. Must agree everywhere the claim bridge is
/// built (the prover-side `StepCtx` and the `ProofBuilder`), or the claim's
/// `com` would not match the rx the proof carries.
pub(crate) fn claim_bridge_alpha<C: Cycle>(
    bridge_alpha: C::ScalarField,
    slot: usize,
) -> C::ScalarField {
    use ragu_arithmetic::ff::Field;
    bridge_alpha.pow_vartime([(5 + slot) as u64])
}

/// Builds poly-query claim `slot`'s bridge stage rx: a stage whose wires are
/// the claim's host commitment.
pub(crate) fn claim_bridge_rx<C: Cycle, R: Rank>(
    slot: usize,
    alpha: C::ScalarField,
    host: C::HostCurve,
) -> Result<sparse::Polynomial<C::ScalarField, R>> {
    use ragu_circuits::staging::StageExt;

    use crate::internal::nested::stages::claim_bridge as cb;
    let witness = cb::Witness { host };
    match slot {
        0 => cb::Stage0::<C::HostCurve, R>::rx(alpha, &witness),
        1 => cb::Stage1::<C::HostCurve, R>::rx(alpha, &witness),
        2 => cb::Stage2::<C::HostCurve, R>::rx(alpha, &witness),
        3 => cb::Stage3::<C::HostCurve, R>::rx(alpha, &witness),
        _ => unreachable!("NUM_POLY_QUERY_SLOTS is 4"),
    }
}

/// The nested-curve commitment to claim `slot`'s bridge stage — the value a
/// claim carries as its `com`.
pub(crate) fn claim_bridge_commitment<C: Cycle, R: Rank>(
    params: &C::Params,
    slot: usize,
    alpha: C::ScalarField,
    host: C::HostCurve,
) -> Result<C::NestedCurve> {
    Ok(claim_bridge_rx::<C, R>(slot, alpha, host)?.commit_to_affine(C::nested_generators(params)))
}

/// The canonical padding claim used to fill unused poly-query slots (see
/// [`NUM_POLY_QUERY_SLOTS`](crate::NUM_POLY_QUERY_SLOTS)): the constant
/// polynomial $1$, opened at $x = 0$ to $y = 1$, with its (never-identity)
/// host commitment and nested bridge commitment.
pub(crate) struct PaddingClaim<C: Cycle, R: Rank> {
    pub poly: sparse::Polynomial<C::CircuitField, R>,
    pub host: C::HostCurve,
    pub x: C::CircuitField,
    pub y: C::CircuitField,
}

impl<C: Cycle, R: Rank> PaddingClaim<C, R> {
    pub fn new(params: &C::Params) -> Result<Self> {
        use ragu_arithmetic::ff::Field;
        let poly =
            sparse::Polynomial::<C::CircuitField, R>::from_coeffs(vec![C::CircuitField::ONE]);
        let host = poly.commit_to_affine::<C::HostCurve>(C::host_generators(params));
        Ok(PaddingClaim {
            poly,
            host,
            x: C::CircuitField::ZERO,
            y: C::CircuitField::ONE,
        })
    }
}
