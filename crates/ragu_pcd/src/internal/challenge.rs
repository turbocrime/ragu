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

use crate::internal::nested::RxIndex;

/// The exponent of `bridge_alpha` for a blinded bridge stage: its position in
/// the ordering `outer_error`, `ab`, `query`, `eval`, offset past the
/// unusable zeroth power. Deriving every exponent from a single ordering
/// keeps all blinds distinct by construction. `preamble`, `s_prime`,
/// `inner_error` and `f` are absent: the fuse stages blind them with an
/// in-circuit challenge, and this panics on them.
pub(crate) fn bridge_alpha_exponent(idx: RxIndex) -> u64 {
    match idx {
        RxIndex::BridgeOuterError => 1,
        RxIndex::BridgeAB => 2,
        RxIndex::BridgeQuery => 3,
        RxIndex::BridgeEval => 4,
        _ => panic!("not blinded from bridge_alpha: {idx:?}"),
    }
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

/// A host commitment's affine coordinates, canonically embedded in the circuit
/// field — one element per coordinate, `lo + 2^128·hi` over the limbs
/// [`host_limbs`] splits (and bounds: a coordinate is below `2^254`, so the
/// embedding is injective and every embedded value fits the circuit field).
pub(crate) fn host_coords<C: Cycle>(host: C::HostCurve) -> Result<[C::CircuitField; 2]> {
    let [x_lo, x_hi, y_lo, y_hi] = host_limbs(host)?;
    Ok([
        embed_coordinate::<C::CircuitField>(x_lo, x_hi),
        embed_coordinate::<C::CircuitField>(y_lo, y_hi),
    ])
}

/// `lo + 2^128·hi` in `F`. With `hi < 2^126` (the [`host_limbs`] bound) the
/// result is below `2^254 < |F|`, so no reduction occurs.
fn embed_coordinate<F: PrimeField>(lo: u128, hi: u128) -> F {
    let shift = F::from_u128(1 << 64).square();
    F::from_u128(lo) + shift * F::from_u128(hi)
}

/// The framework polynomial `q` for a proof's recorded claim hosts: per slot,
/// the two [`host_coords`] of the host commitment, slot-major.
///
/// Fully deterministic from the recorded hosts — any party can rebuild it, so
/// it is rebuilt rather than carried. Empty when there are no slots: the
/// feature vanishes at `POLYS = 0`.
///
/// `q` is what binds a step's instance-bound coordinate wires to the real
/// commitments: `_10_p` folds `(q, commit(q))` into the accumulator,
/// `compute_v` re-derives `q(u)` from the child's coordinate instance wires,
/// and the deferred PCS opening forces the two to agree.
pub(crate) fn claim_coord_poly<C: Cycle, R: Rank>(
    hosts: impl IntoIterator<Item = C::HostCurve>,
) -> Result<sparse::Polynomial<C::CircuitField, R>> {
    let mut coeffs = alloc::vec::Vec::new();
    for host in hosts {
        coeffs.extend(host_coords::<C>(host)?);
    }
    Ok(sparse::Polynomial::from_coeffs(coeffs))
}

/// The host-curve commitment to [`claim_coord_poly`].
pub(crate) fn claim_coord_commitment<C: Cycle, R: Rank>(
    params: &C::Params,
    hosts: impl IntoIterator<Item = C::HostCurve>,
) -> Result<C::HostCurve> {
    Ok(claim_coord_poly::<C, R>(hosts)?
        .commit_to_affine::<C::HostCurve>(C::host_generators(params)))
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

/// The fixed field element filling an unfilled challenge-input position: the
/// zeroth nested generator's `x` coordinate — a params-derived constant, like
/// the point it comes from.
///
/// A challenge slot's sponge absorbs a full complement of
/// [`ChallengeLayout::width`](crate::framework_hooks::ChallengeLayout::width)
/// whether or not the caller supplied them all, so the prover, the root
/// verifier, and the `challenge_binding` circuit agree on the sponge's shape
/// by construction.
pub(crate) fn sentinel_element<C: Cycle>(params: &C::Params) -> C::CircuitField {
    use ragu_arithmetic::FixedGenerators;

    *C::nested_generators(params).g()[0]
        .coordinates()
        .expect("a fixed generator is not the identity")
        .x()
}

/// Hashes a challenge slot's input elements into the challenge they derive.
///
/// The native counterpart of what the `challenge_binding` circuit enforces
/// in-circuit for every child slot; the two must agree exactly. Kept as one
/// function so a change to the sponge shape cannot silently desync the prover,
/// the root verifier, and the circuit.
///
/// [`challenge_binding`]: crate::internal::native::circuits::challenge_binding
pub(crate) fn challenge_from_elements<C: Cycle>(
    params: &C::Params,
    inputs: &[C::CircuitField],
) -> Result<C::CircuitField> {
    use ragu_core::{drivers::emulator::Emulator, maybe::Maybe};
    use ragu_primitives::{Element, GadgetExt, poseidon::Sponge};

    let mut dr = Emulator::execute();
    let mut sponge = Sponge::new(&mut dr, C::circuit_poseidon(params));
    for &input in inputs {
        let element = Element::constant(&mut dr, input);
        element.write(&mut dr, &mut sponge)?;
    }
    let challenge = sponge.squeeze(&mut dr)?;
    Ok(*challenge.value().take())
}

/// Pads a `derive_challenge` call's inputs to the slot's full complement with
/// the sentinel and hashes them: the whole prover-side derivation.
pub(crate) fn elements_challenge<C: Cycle>(
    params: &C::Params,
    inputs: &[C::CircuitField],
    width: usize,
) -> Result<(alloc::vec::Vec<C::CircuitField>, C::CircuitField)> {
    debug_assert!(inputs.len() <= width);
    let mut padded = inputs.to_vec();
    padded.resize(width, sentinel_element::<C>(params));
    let challenge = challenge_from_elements::<C>(params, &padded)?;
    Ok((padded, challenge))
}

#[cfg(test)]
mod tests {
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
    /// circuit — so **no registry digest covers them**. Two stages colliding
    /// on one blind would be silent; this test is the only thing that would
    /// notice.
    #[test]
    fn bridge_alpha_exponents_are_the_expected_series() {
        // Spelled out so a reordering has to be deliberate.
        assert_eq!(bridge_alpha_exponent(RxIndex::BridgeOuterError), 1);
        assert_eq!(bridge_alpha_exponent(RxIndex::BridgeAB), 2);
        assert_eq!(bridge_alpha_exponent(RxIndex::BridgeQuery), 3);
        assert_eq!(bridge_alpha_exponent(RxIndex::BridgeEval), 4);
    }

    /// The bridges the fuse stages blind with an in-circuit challenge are not
    /// on this series at all.
    #[test]
    #[should_panic(expected = "not blinded from bridge_alpha")]
    fn unblinded_bridges_are_rejected() {
        bridge_alpha_exponent(RxIndex::BridgeF);
    }
}
