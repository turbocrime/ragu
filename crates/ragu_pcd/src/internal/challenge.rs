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

/// The stage blind for challenge `slot`'s **application-circuit** stage.
///
/// A separate source from [`claim_bridge_alpha`] because this stage lives on
/// the native side: its polynomial is over `CircuitField`, so its blind must be
/// too.
pub(crate) fn challenge_stage_alpha<C: Cycle>(
    challenge_alpha: C::CircuitField,
    slot: usize,
) -> C::CircuitField {
    use ragu_arithmetic::ff::Field;
    challenge_alpha.pow_vartime([(1 + slot) as u64])
}

/// The stage blind for challenge `slot`'s **nested** bridge stage. Continues
/// the `bridge_alpha` power series past the poly-query claim slots so no two
/// bridge stages share a blind.
pub(crate) fn challenge_bridge_alpha<C: Cycle>(
    bridge_alpha: C::ScalarField,
    slot: usize,
) -> C::ScalarField {
    use ragu_arithmetic::ff::Field;
    bridge_alpha.pow_vartime([(5 + crate::NUM_POLY_QUERY_SLOTS + slot) as u64])
}

/// Builds challenge `slot`'s bridge stage rx: a stage whose wires are the
/// slot's host-curve stage commitment.
pub(crate) fn challenge_bridge_rx<C: Cycle, R: Rank>(
    slot: usize,
    alpha: C::ScalarField,
    host: C::HostCurve,
) -> Result<sparse::Polynomial<C::ScalarField, R>> {
    use ragu_circuits::staging::StageExt;

    use crate::internal::nested::stages::challenge_bridge as cb;
    let witness = cb::Witness { host };
    match slot {
        0 => cb::Stage0::<C::HostCurve, R>::rx(alpha, &witness),
        1 => cb::Stage1::<C::HostCurve, R>::rx(alpha, &witness),
        _ => unreachable!("NUM_CHALLENGE_SLOTS is 2"),
    }
}

/// The nested-curve commitment to challenge `slot`'s bridge stage — the point
/// the native side witnesses and hashes into the challenge.
pub(crate) fn challenge_bridge_commitment<C: Cycle, R: Rank>(
    params: &C::Params,
    slot: usize,
    alpha: C::ScalarField,
    host: C::HostCurve,
) -> Result<C::NestedCurve> {
    Ok(challenge_bridge_rx::<C, R>(slot, alpha, host)?
        .commit_to_affine(C::nested_generators(params)))
}

/// Hashes a bridged challenge-stage commitment into the challenge it derives.
///
/// The native counterpart of what the `challenge_binding` circuit enforces
/// in-circuit for every child slot; the two must agree exactly. Kept as one
/// function so a change to the sponge shape cannot silently desync the prover,
/// the root verifier, and the circuit.
///
/// [`challenge_binding`]: crate::internal::native::circuits::challenge_binding
pub(crate) fn challenge_from_point<C: Cycle>(
    params: &C::Params,
    point: C::NestedCurve,
) -> Result<C::CircuitField> {
    use ragu_core::{drivers::emulator::Emulator, maybe::Maybe};
    use ragu_primitives::{GadgetExt, Point, poseidon::Sponge};

    let mut dr = Emulator::execute();
    let point = Point::constant(&mut dr, point)?;
    let mut sponge = Sponge::new(&mut dr, C::circuit_poseidon(params));
    point.write(&mut dr, &mut sponge)?;
    let challenge = sponge.squeeze(&mut dr)?;
    Ok(*challenge.value().take())
}

/// Derives challenge `slot`'s value from the values its stage commits.
///
/// The full prover-side chain: build the application-side stage rx from
/// `inputs`, commit it on the host generators, bridge that host point onto the
/// nested curve, and hash the bridged point. The result is a `CircuitField`
/// element — the field the application circuit works in — which is exactly what
/// the bridge is for.
pub(crate) fn staged_challenge<C: Cycle, R: Rank>(
    params: &C::Params,
    slot: usize,
    challenge_alpha: C::CircuitField,
    bridge_alpha: C::ScalarField,
    inputs: [C::CircuitField; crate::CHALLENGE_WIDTH],
) -> Result<(C::NestedCurve, C::CircuitField)> {
    use crate::step::internal::challenge_stage;

    let stage_rx = challenge_stage::stage_rx::<C::CircuitField, R>(
        slot,
        challenge_stage_alpha::<C>(challenge_alpha, slot),
        inputs,
    )?;
    let host = stage_rx.commit_to_affine::<C::HostCurve>(C::host_generators(params));
    if host.coordinates().into_option().is_none() {
        return Err(Error::InvalidWitness(
            "challenge stage commitment is the identity and cannot be bridged".into(),
        ));
    }
    let bridged = challenge_bridge_commitment::<C, R>(
        params,
        slot,
        challenge_bridge_alpha::<C>(bridge_alpha, slot),
        host,
    )?;

    let challenge = challenge_from_point::<C>(params, bridged)?;

    Ok((bridged, challenge))
}
