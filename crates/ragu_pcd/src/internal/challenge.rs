//! The poly-query commitment scheme: Pedersen-commit a polynomial on the host
//! curve and bridge the resulting point onto the nested curve so it can be
//! witnessed in-circuit. Also the native side of challenge derivation: hashing
//! the points a step supplies into the challenge they derive.

use alloc::vec;

use ragu_arithmetic::{
    CurveAffine, Cycle,
    ff::{Field, PrimeField},
};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Error, Result};

use crate::internal::nested::{
    RxIndex,
    stages::{claim_bridge, host_bridge},
};

/// The bridge stages whose blinds come from the proof's shared `bridge_alpha`,
/// in the order that assigns their exponents.
///
/// A stage's blind is `bridge_alpha^(i + 1)` for its position `i` here; the
/// series starts at 1 because `α⁰ = 1` is no blind at all. Deriving every
/// exponent from a single ordering keeps all blinds distinct by construction.
/// `preamble`, `s_prime`, `inner_error` and `f` are absent: the fuse stages
/// blind them with an in-circuit challenge, and [`bridge_alpha_exponent`]
/// panics on them.
///
/// This is the *specification* of the ordering:
/// `bridge_alpha_exponents_are_the_expected_series` checks
/// [`bridge_alpha_exponent`]'s direct computation against it.
#[cfg(test)]
fn blinded_bridges(num_polys: usize) -> impl Iterator<Item = RxIndex> {
    // The four `cached_bridge!` stages first, then the per-slot claim bridges,
    // which chain through `Parent` and so cannot use that macro.
    [
        RxIndex::BridgeOuterError,
        RxIndex::BridgeAB,
        RxIndex::BridgeQuery,
        RxIndex::BridgeEval,
    ]
    .into_iter()
    .chain((0..num_polys).map(|slot| RxIndex::BridgeClaim(slot as u32)))
}

/// How many entries [`blinded_bridges`] yields before the per-slot claim
/// bridges: the four `cached_bridge!` stages.
const NUM_CACHED_BRIDGES: u64 = 4;

/// The exponent of `bridge_alpha` for a blinded bridge stage — its position in
/// [`blinded_bridges`], offset past the unusable zeroth power.
///
/// The claim slots come last, so an exponent depends only on the entry's own
/// position — no capacity parameter needed.
/// `bridge_alpha_exponents_are_the_expected_series` pins this against
/// [`blinded_bridges`].
pub(crate) fn bridge_alpha_exponent(idx: RxIndex) -> u64 {
    match idx {
        RxIndex::BridgeOuterError => 1,
        RxIndex::BridgeAB => 2,
        RxIndex::BridgeQuery => 3,
        RxIndex::BridgeEval => 4,
        RxIndex::BridgeClaim(slot) => NUM_CACHED_BRIDGES + u64::from(slot) + 1,
        _ => panic!("not blinded from bridge_alpha: {idx:?}"),
    }
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

/// Bits admitted in a coordinate's high half.
///
/// Two short of a limb's 128, which is what makes the decomposition canonical:
/// the largest value `lo + 2^128·hi` can then take is `2^254 - 1`, below both
/// Pasta moduli, so no coordinate has a wrapped second decomposition. The cost
/// is a completeness bound: a commitment with a coordinate at or above `2^254`
/// — a `~2^-129` fraction of the field — cannot be witnessed.
const HIGH_BITS: usize = 126;

/// The four 128-bit limbs `[x_lo, x_hi, y_lo, y_hi]` of a host commitment's
/// coordinates — the consumer's own split of `to_repr()` into 16-byte halves,
/// so hashing these values reproduces exactly the digest computed natively
/// from the same commitment.
///
/// Errors rather than truncating when a coordinate does not fit: see
/// [`HIGH_BITS`], whose width bound is what makes the split canonical.
pub(crate) fn host_limbs<C: CurveAffine>(host: C) -> Result<[u128; 4]> {
    let coordinates = host.coordinates().into_option().ok_or_else(|| {
        Error::InvalidWitness(
            "the identity has no coordinates and cannot be witnessed in-circuit".into(),
        )
    })?;

    let mut limbs = [0u128; 4];
    for (coordinate, pair) in [*coordinates.x(), *coordinates.y()]
        .into_iter()
        .zip(limbs.chunks_mut(2))
    {
        let repr = coordinate.to_repr();
        let (lo, hi) = split_coordinate(repr.as_ref())?;
        pair[0] = lo;
        pair[1] = hi;
    }

    Ok(limbs)
}

/// Splits a coordinate's canonical little-endian bytes into 16-byte halves,
/// rejecting values at or above `2^254`.
fn split_coordinate(bytes: &[u8]) -> Result<(u128, u128)> {
    if bytes.len() < 32 {
        return Err(Error::InvalidWitness(
            "a coordinate narrower than 32 bytes is not a supported cycle's".into(),
        ));
    }

    let lo = u128::from_le_bytes(bytes[..16].try_into().expect("16 bytes"));
    let hi = u128::from_le_bytes(bytes[16..32].try_into().expect("16 bytes"));

    if hi >> HIGH_BITS != 0 || bytes[32..].iter().any(|byte| *byte != 0) {
        return Err(Error::InvalidWitness(
            "a polynomial commitment with a coordinate at or above 2^254 cannot be \
             decomposed canonically and so cannot be witnessed in-circuit"
                .into(),
        ));
    }

    Ok((lo, hi))
}

/// The framework polynomial `q` for a proof's recorded claim hosts: per slot,
/// four coefficients `lift(l_k)` of the host commitment's canonical limbs
/// `[x_lo, x_hi, y_lo, y_hi]`, slot-major.
///
/// Fully deterministic from the recorded hosts — any party can rebuild it, so
/// it is rebuilt rather than carried. Empty when there are no slots: the limb
/// feature vanishes at `POLYS = 0`.
///
/// `q` is what binds a step's instance-bound lifts to the real commitments:
/// `_10_p` folds `(q, commit(q))` into the accumulator, `compute_v` re-derives
/// `q(u)` from the child's lift instance wires, and the deferred PCS opening
/// forces the two to agree.
pub(crate) fn claim_lift_poly<C: Cycle, R: Rank>(
    hosts: impl IntoIterator<Item = C::HostCurve>,
) -> Result<sparse::Polynomial<C::CircuitField, R>> {
    let mut coeffs = alloc::vec::Vec::new();
    for host in hosts {
        let limbs = host_limbs(host)?;
        coeffs.extend(
            limbs
                .into_iter()
                .map(ragu_primitives::lift_endoscalar::<C::CircuitField>),
        );
    }
    Ok(sparse::Polynomial::from_coeffs(coeffs))
}

/// The host-curve commitment to [`claim_lift_poly`].
pub(crate) fn claim_lift_commitment<C: Cycle, R: Rank>(
    params: &C::Params,
    hosts: impl IntoIterator<Item = C::HostCurve>,
) -> Result<C::HostCurve> {
    Ok(
        claim_lift_poly::<C, R>(hosts)?
            .commit_to_affine::<C::HostCurve>(C::host_generators(params)),
    )
}

/// The stage blind for poly-query claim `slot`, derived from the proof's
/// shared `bridge_alpha` source. Shared so the claim bridge's two build sites
/// (the prover-side `StepCtx` and the `ProofBuilder`) agree.
pub(crate) fn claim_bridge_alpha<C: Cycle>(
    bridge_alpha: C::ScalarField,
    slot: usize,
) -> C::ScalarField {
    bridge_alpha.pow_vartime([bridge_alpha_exponent(RxIndex::BridgeClaim(slot as u32))])
}

/// Builds poly-query claim `slot`'s bridge stage rx: a stage whose wires are
/// the claim's host commitment. The slot is an index into the claim-bridge
/// run's layout, so the slot count can be an application parameter.
pub(crate) fn claim_bridge_rx<C: Cycle, R: Rank>(
    slot: usize,
    alpha: C::ScalarField,
    host: C::HostCurve,
    polys: usize,
) -> Result<sparse::Polynomial<C::ScalarField, R>> {
    let witness = host_bridge::Witness { host };
    claim_bridge::layout::<C::HostCurve, R>(polys).rx_configured(
        slot,
        alpha,
        &claim_bridge::Slot::<C::HostCurve, R>::default(),
        &witness,
    )
}

/// The nested-curve commitment to claim `slot`'s bridge stage — the value a
/// claim carries as its `bridge_com`.
pub(crate) fn claim_bridge_commitment<C: Cycle, R: Rank>(
    params: &C::Params,
    slot: usize,
    alpha: C::ScalarField,
    host: C::HostCurve,
    polys: usize,
) -> Result<C::NestedCurve> {
    Ok(commit_bridge::<C, R>(
        params,
        claim_bridge_rx::<C, R>(slot, alpha, host, polys)?,
    ))
}

/// The canonical padding claim for an unused poly-query slot (see
/// the application's poly capacity): its host commitment
/// and its opening $(x, y) = (0, 1)$.
///
/// A slot cannot be padded with zeros — `commit(0)` is the identity, which no
/// [`Point`](ragu_primitives::Point) can witness — so the padding is a *real*
/// claim that happens to be trivially true: the constant polynomial $1$, whose
/// commitment is exactly `g[0]` and whose value at any $x$ is $1$. It travels
/// the same path as a claim the step raised.
///
/// The three values are returned together because they are one claim: $y$ is
/// [`padding_poly`] evaluated at $x$.
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

/// The fixed non-identity point filling an unfilled challenge-input position:
/// the zeroth nested generator.
///
/// A challenge slot's sponge absorbs a full complement of
/// [`ChallengeLayout::width`](crate::framework_hooks::ChallengeLayout::width)
/// whether or not the caller supplied them all, so the prover, the root
/// verifier, and the `challenge_binding` circuit agree on the sponge's shape
/// by construction.
pub(crate) fn sentinel_point<C: Cycle>(params: &C::Params) -> C::NestedCurve {
    use ragu_arithmetic::FixedGenerators;

    C::nested_generators(params).g()[0]
}

/// Hashes a challenge slot's input points into the challenge they derive.
///
/// The native counterpart of what the `challenge_binding` circuit enforces
/// in-circuit for every child slot; the two must agree exactly. Kept as one
/// function so a change to the sponge shape cannot silently desync the prover,
/// the root verifier, and the circuit.
///
/// [`challenge_binding`]: crate::internal::native::circuits::challenge_binding
pub(crate) fn challenge_from_points<C: Cycle>(
    params: &C::Params,
    points: &[C::NestedCurve],
) -> Result<C::CircuitField> {
    use ragu_core::{drivers::emulator::Emulator, maybe::Maybe};
    use ragu_primitives::{GadgetExt, Point, poseidon::Sponge};

    let mut dr = Emulator::execute();
    let mut sponge = Sponge::new(&mut dr, C::circuit_poseidon(params));
    for &point in points {
        let point = Point::constant(&mut dr, point)?;
        point.write(&mut dr, &mut sponge)?;
    }
    let challenge = sponge.squeeze(&mut dr)?;
    Ok(*challenge.value().take())
}

/// Pads a `derive_challenge` call's points to the slot's full complement with
/// the sentinel and hashes them: the whole prover-side derivation.
pub(crate) fn points_challenge<C: Cycle>(
    params: &C::Params,
    points: &[C::NestedCurve],
    width: usize,
) -> Result<(alloc::vec::Vec<C::NestedCurve>, C::CircuitField)> {
    debug_assert!(points.len() <= width);
    let mut padded = points.to_vec();
    padded.resize(width, sentinel_point::<C>(params));
    let challenge = challenge_from_points::<C>(params, &padded)?;
    Ok((padded, challenge))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    /// The limbs are the coordinates: `lo + 2^128·hi`, recomposed in the
    /// field, is the coordinate itself.
    ///
    /// Longhand on purpose — the shift is built by doubling, and the expected
    /// value never calls the code under test, so the assertion checks that the
    /// split really is the inverse of recomposition rather than restating it.
    #[test]
    fn limbs_recompose_to_the_coordinates() {
        use ragu_arithmetic::{group::Group as _, pasta_curves::group::Curve};
        use ragu_pasta::{EqAffine, Fp};

        // The host curve's scalars are the *circuit* field — the fact the
        // whole limb mechanism exists to exploit.
        let host = (<EqAffine as CurveAffine>::CurveExt::generator() * Fp::from(7)).to_affine();
        let limbs = host_limbs(host).expect("the generator's multiple is decomposable");

        let mut shift = <EqAffine as CurveAffine>::Base::ONE;
        for _ in 0..128 {
            shift = shift.double();
        }

        let coordinates = host.coordinates().unwrap();
        for (coordinate, pair) in [*coordinates.x(), *coordinates.y()]
            .into_iter()
            .zip(limbs.chunks(2))
        {
            let recomposed = <EqAffine as CurveAffine>::Base::from_u128(pair[0])
                + <EqAffine as CurveAffine>::Base::from_u128(pair[1]) * shift;
            assert_eq!(recomposed, coordinate, "the limbs are not the coordinate");
        }
    }

    /// A high half with bit 126 or 127 set encodes a value at or above
    /// `2^254`, which has no canonical decomposition and is refused.
    #[test]
    fn a_coordinate_at_2_254_is_rejected() {
        let mut bytes = [0u8; 32];

        bytes[31] = 0x40; // bit 254
        assert!(split_coordinate(&bytes).is_err());

        bytes[31] = 0x20; // bit 253, the top admissible bit
        assert!(split_coordinate(&bytes).is_ok());
    }

    /// The identity has no coordinates, so it cannot be witnessed — the same
    /// rejection [`Point::alloc`](ragu_primitives::Point::alloc) makes.
    #[test]
    fn the_identity_is_rejected() {
        use ragu_arithmetic::group::CurveAffine as _;

        assert!(host_limbs(ragu_pasta::EqAffine::identity()).is_err());
    }

    /// Pins the `bridge_alpha` exponent series.
    ///
    /// These blinds are prover-side — derived at proof time, never part of a
    /// circuit — so **no registry digest covers them**. Reordering
    /// [`blinded_bridges`] would silently change every blind from the edit
    /// onward, and two stages colliding on one blind would be silent too. This
    /// test is the only thing that would notice.
    ///
    /// Distinctness follows from mapping the whole series through
    /// [`bridge_alpha_exponent`] and getting `1..=n` with no gaps: that is only
    /// possible if every entry lands on its own exponent. This is also what ties
    /// the direct computation in `bridge_alpha_exponent` to the ordering
    /// [`blinded_bridges`] declares, so the two cannot drift apart.
    #[test]
    fn bridge_alpha_exponents_are_the_expected_series() {
        const POLYS: usize = 8;
        let series: Vec<u64> = blinded_bridges(POLYS).map(bridge_alpha_exponent).collect();
        let expected: Vec<u64> = (1..=series.len() as u64).collect();
        assert_eq!(series, expected, "exponents must be 1..=n with no gaps");

        // The four cached bridges, then the claim slots. Spelled out so a
        // reordering has to be deliberate.
        assert_eq!(bridge_alpha_exponent(RxIndex::BridgeOuterError), 1);
        assert_eq!(bridge_alpha_exponent(RxIndex::BridgeAB), 2);
        assert_eq!(bridge_alpha_exponent(RxIndex::BridgeQuery), 3);
        assert_eq!(bridge_alpha_exponent(RxIndex::BridgeEval), 4);
        assert_eq!(bridge_alpha_exponent(RxIndex::BridgeClaim(0)), 5);
        assert_eq!(
            bridge_alpha_exponent(RxIndex::BridgeClaim(POLYS as u32 - 1)),
            4 + POLYS as u64
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
