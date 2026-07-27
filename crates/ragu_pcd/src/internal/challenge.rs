//! The poly-query commitment scheme: Pedersen-commit a polynomial on the host
//! curve and bridge the resulting point onto the nested curve so it can be
//! witnessed in-circuit.

use alloc::vec;

use ragu_arithmetic::{CurveAffine, Cycle, ff::Field};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::StageExt,
};
use ragu_core::{Error, Result};

use crate::internal::nested::{
    RxIndex,
    stages::{challenge_bridge, claim_bridge, host_bridge},
};

/// The bridge stages whose blinds come from the proof's shared `bridge_alpha`,
/// in the order that assigns their exponents.
///
/// A stage's blind is `bridge_alpha^(i + 1)` for its position `i` here; the
/// series starts at 1 because `α⁰ = 1` is no blind at all. The requirement is
/// that no two bridge stages share a blind — deriving every exponent from a
/// single ordering makes that true *by construction*, rather than by separate
/// rules per family that have to be kept in agreement. It also means the layout
/// follows the slot counts automatically.
///
/// Not every bridge stage is here. `preamble`, `s_prime`, `inner_error` and `f`
/// are set by the fuse stages, which blind them with an in-circuit challenge
/// instead — [`bridge_alpha_exponent`] panics on those.
fn blinded_bridges() -> impl Iterator<Item = RxIndex> {
    // The four `cached_bridge!` stages first, then the per-slot bridges, which
    // chain through `Parent` and so cannot use that macro.
    [
        RxIndex::BridgeOuterError,
        RxIndex::BridgeAB,
        RxIndex::BridgeQuery,
        RxIndex::BridgeEval,
    ]
    .into_iter()
    .chain((0..crate::NUM_POLY_SLOTS).map(|slot| RxIndex::BridgeClaim(slot as u32)))
    .chain((0..crate::NUM_CHALLENGE_SLOTS).map(|slot| RxIndex::BridgeChallenge(slot as u32)))
}

/// The exponent of `bridge_alpha` for a blinded bridge stage — its position in
/// [`blinded_bridges`], offset past the unusable zeroth power.
pub(crate) fn bridge_alpha_exponent(idx: RxIndex) -> u64 {
    let position = blinded_bridges()
        .position(|bridge| bridge == idx)
        .unwrap_or_else(|| panic!("not blinded from bridge_alpha: {idx:?}"));
    position as u64 + 1
}

/// Commits a bridge stage rx on the nested generators.
fn commit_bridge<C: Cycle, R: Rank>(
    params: &C::Params,
    rx: sparse::Polynomial<C::ScalarField, R>,
) -> C::NestedCurve {
    rx.commit_to_affine(C::nested_generators(params))
}

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
    bridge_alpha.pow_vartime([bridge_alpha_exponent(RxIndex::BridgeClaim(slot as u32))])
}

/// Builds poly-query claim `slot`'s bridge stage rx: a stage whose wires are
/// the claim's host commitment.
///
/// The slot is an index into the claim-bridge run's layout rather than a
/// distinct type, so this reads the stage's position off the layout instead of
/// dispatching. That is what lets the slot count be an application parameter:
/// there is nothing here to widen when it changes.
pub(crate) fn claim_bridge_rx<C: Cycle, R: Rank>(
    slot: usize,
    alpha: C::ScalarField,
    host: C::HostCurve,
) -> Result<sparse::Polynomial<C::ScalarField, R>> {
    let witness = host_bridge::Witness { host };
    claim_bridge::layout::<C::HostCurve, R>().rx_configured(
        slot,
        alpha,
        &claim_bridge::Slot::<C::HostCurve, R>::default(),
        &witness,
    )
}

/// The nested-curve commitment to claim `slot`'s bridge stage — the value a
/// claim carries as its `com`.
pub(crate) fn claim_bridge_commitment<C: Cycle, R: Rank>(
    params: &C::Params,
    slot: usize,
    alpha: C::ScalarField,
    host: C::HostCurve,
) -> Result<C::NestedCurve> {
    Ok(commit_bridge::<C, R>(
        params,
        claim_bridge_rx::<C, R>(slot, alpha, host)?,
    ))
}

/// The canonical padding claim for an unused poly-query slot (see
/// [`NUM_POLY_SLOTS`](crate::NUM_POLY_SLOTS)): its host commitment
/// and its opening $(x, y) = (0, 1)$.
///
/// A slot cannot be padded with zeros — `commit(0)` is the identity, which no
/// [`Point`](ragu_primitives::Point) can witness — so the padding is a *real*
/// claim that happens to be trivially true: the constant polynomial $1$, whose
/// value at any $x$ is $1$. Nothing about it is special-cased downstream; it
/// travels the same path as a claim the step raised.
///
/// The commitment needs no multi-scalar multiplication. `commit` sends the
/// coefficient of $X^d$ to `g[d]`, so committing $1$ is exactly `g[0]` — which
/// is also why it can never be the identity.
///
/// The three values are returned together because they are one claim: $y$ is
/// [`padding_poly`] evaluated at $x$, and changing either end alone would make
/// the claim false.
pub(crate) fn padding_claim<C: Cycle>(
    params: &C::Params,
) -> (C::HostCurve, C::CircuitField, C::CircuitField) {
    use ragu_arithmetic::FixedGenerators;

    let host = C::host_generators(params).g()[0];
    (host, C::CircuitField::ZERO, C::CircuitField::ONE)
}

/// The padding claim's polynomial, $p(X) = 1$, for the carriers that hold whole
/// polynomials rather than openings. Its commitment is [`padding_claim`]'s.
pub(crate) fn padding_poly<C: Cycle, R: Rank>() -> sparse::Polynomial<C::CircuitField, R> {
    sparse::Polynomial::from_coeffs(vec![C::CircuitField::ONE])
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
    challenge_alpha.pow_vartime([(1 + slot) as u64])
}

/// The stage blind for challenge `slot`'s **nested** bridge stage. Continues
/// the `bridge_alpha` power series past the poly-query claim slots so no two
/// bridge stages share a blind.
pub(crate) fn challenge_bridge_alpha<C: Cycle>(
    bridge_alpha: C::ScalarField,
    slot: usize,
) -> C::ScalarField {
    bridge_alpha.pow_vartime([bridge_alpha_exponent(RxIndex::BridgeChallenge(slot as u32))])
}

/// Builds challenge `slot`'s bridge stage rx: a stage whose wires are the
/// slot's host-curve stage commitment.
///
/// Dispatches on the slot because each slot is a distinct type with distinct
/// generator positions.
pub(crate) fn challenge_bridge_rx<C: Cycle, R: Rank>(
    slot: usize,
    alpha: C::ScalarField,
    host: C::HostCurve,
) -> Result<sparse::Polynomial<C::ScalarField, R>> {
    let witness = host_bridge::Witness { host };
    match slot {
        0 => challenge_bridge::Stage0::<C::HostCurve, R>::rx(alpha, &witness),
        1 => challenge_bridge::Stage1::<C::HostCurve, R>::rx(alpha, &witness),
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
    Ok(commit_bridge::<C, R>(
        params,
        challenge_bridge_rx::<C, R>(slot, alpha, host)?,
    ))
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

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    /// Pins the `bridge_alpha` exponent series.
    ///
    /// These blinds are prover-side — derived at proof time, never part of a
    /// circuit — so **no registry digest covers them**. Reordering
    /// [`blinded_bridges`] would silently change every blind from the edit
    /// onward, and two stages colliding on one blind would be silent too. This
    /// test is the only thing that would notice.
    ///
    /// Distinctness follows from the series being `1..=n`, which is what
    /// deriving the exponent from a position in a single ordering buys.
    #[test]
    fn bridge_alpha_exponents_are_the_expected_series() {
        let series: Vec<u64> = blinded_bridges().map(bridge_alpha_exponent).collect();
        let expected: Vec<u64> = (1..=series.len() as u64).collect();
        assert_eq!(series, expected, "exponents must be 1..=n with no gaps");

        // The four cached bridges, then the claim slots, then the challenge
        // slots. Spelled out so a reordering has to be deliberate.
        assert_eq!(bridge_alpha_exponent(RxIndex::BridgeOuterError), 1);
        assert_eq!(bridge_alpha_exponent(RxIndex::BridgeAB), 2);
        assert_eq!(bridge_alpha_exponent(RxIndex::BridgeQuery), 3);
        assert_eq!(bridge_alpha_exponent(RxIndex::BridgeEval), 4);
        assert_eq!(bridge_alpha_exponent(RxIndex::BridgeClaim(0)), 5);
        assert_eq!(
            bridge_alpha_exponent(RxIndex::BridgeClaim(crate::NUM_POLY_SLOTS as u32 - 1)),
            4 + crate::NUM_POLY_SLOTS as u64
        );
        assert_eq!(
            bridge_alpha_exponent(RxIndex::BridgeChallenge(0)),
            5 + crate::NUM_POLY_SLOTS as u64
        );
    }

    /// The bridges the fuse stages blind with an in-circuit challenge are not
    /// on this series at all.
    #[test]
    #[should_panic(expected = "not blinded from bridge_alpha")]
    fn unblinded_bridges_are_rejected() {
        bridge_alpha_exponent(RxIndex::BridgeF);
    }
}
