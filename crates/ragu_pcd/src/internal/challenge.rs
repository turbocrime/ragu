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

/// The framework polynomial `q` for a proof's recorded claim hosts: per slot,
/// the two [`PolyCommitment::host_coords`](crate::PolyCommitment::host_coords)
/// of the host commitment, slot-major.
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
        coeffs.extend(crate::PolyCommitment::<C>::host_coords(host)?);
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

/// The fixed field element filling an unfilled challenge-input position: the
/// zeroth nested generator's `x` coordinate — a params-derived constant, like
/// the point it comes from.
///
/// A challenge slot's sponge absorbs a full complement of
/// [`ChallengeLayout::width`](crate::framework_hooks::ChallengeLayout::width)
/// whether or not the caller supplied them all, so the prover, the root
/// verifier, and the `challenge_binding` circuit agree on the sponge's shape
/// by construction.
fn sentinel_element<C: Cycle>(params: &C::Params) -> C::CircuitField {
    use ragu_arithmetic::FixedGenerators;

    *C::nested_generators(params).g()[0]
        .coordinates()
        .expect("a fixed generator is not the identity")
        .x()
}

/// Pads a challenge slot's inputs to its full complement with the sentinel
/// and hashes them into the challenge they derive: the whole native-side
/// derivation.
///
/// The native counterpart of what the `challenge_binding` circuit enforces
/// in-circuit for every child slot; the two must agree exactly. Kept as one
/// function so a change to the sponge shape cannot silently desync the prover,
/// the root verifier, and the circuit — the verifier re-derives a recorded
/// slot (already full) by passing `width = inputs.len()`, making the padding
/// a no-op.
///
/// [`challenge_binding`]: crate::internal::native::circuits::challenge_binding
pub(crate) fn padded_challenge<C: Cycle>(
    params: &C::Params,
    inputs: &[C::CircuitField],
    width: usize,
) -> Result<(alloc::vec::Vec<C::CircuitField>, C::CircuitField)> {
    use ragu_core::{drivers::emulator::Emulator, maybe::Maybe};
    use ragu_primitives::{Element, GadgetExt, poseidon::Sponge};

    debug_assert!(inputs.len() <= width);
    let mut padded = inputs.to_vec();
    padded.resize(width, sentinel_element::<C>(params));

    let mut dr = Emulator::execute();
    let mut sponge = Sponge::new(&mut dr, C::circuit_poseidon(params));
    for &input in &padded {
        let element = Element::constant(&mut dr, input);
        element.write(&mut dr, &mut sponge)?;
    }
    let challenge = sponge.squeeze(&mut dr)?;
    Ok((padded, *challenge.value().take()))
}

/// The values that pad a step's unused hook slots, computed once at
/// [`finalize`](crate::ApplicationBuilder::finalize) — where the cycle
/// parameters enter — and supplied to every proof as ordinary witness data.
///
/// Every field is a per-application constant: the padding claim's committed
/// polynomial (the constant $1$, whose commitment is `g[0]`), the sentinel
/// element filling an empty challenge-input position, and the challenge a
/// slot of all-sentinel inputs hashes to. They are witness *values* — the
/// wires they fill are locally unconstrained instance wires whose
/// correctness the parent's circuits enforce — so they ride the witness
/// channel into [`Step::witness`](crate::step::Step), absent on
/// structure-only drivers like every other witness value. This is the same
/// padding the trivial proof puts in its slot lists; computing it once keeps
/// the two in one place.
///
/// A poly slot cannot be padded with zeros — `commit(0)` is the identity,
/// which no [`Point`](ragu_primitives::Point) can witness — so the padding is
/// a *real* claim that happens to be trivially true: the constant polynomial
/// $1$, whose commitment is exactly `g[0]` and whose value at any $x$ is $1$.
/// It travels the same path as a claim the step raised.
pub(crate) struct Padding<C: Cycle> {
    /// The padding claim's committed polynomial: the constant $1$ with its
    /// canonical commitment representation.
    pub poly: crate::PolyCommitment<C>,
    /// The padding claim's commitment as the host point itself, `g[0]` —
    /// [`PolyCommitment`](crate::PolyCommitment) keeps only the embedded
    /// coordinates, and a proof's slot lists need the point.
    pub host: C::HostCurve,
    /// The fixed element filling an unfilled challenge-input position.
    pub sentinel: C::CircuitField,
    /// The challenge an all-sentinel slot derives:
    /// `H(sentinel, .., sentinel)` at the application's challenge width.
    /// `None` at width zero, where there is nothing to hash — an application
    /// with challenge slots of width zero could never derive a challenge in
    /// the first place, so the value is only read where it exists.
    pub challenge: Option<C::CircuitField>,
}

impl<C: Cycle> Clone for Padding<C> {
    fn clone(&self) -> Self {
        Self {
            poly: self.poly.clone(),
            host: self.host,
            sentinel: self.sentinel,
            challenge: self.challenge,
        }
    }
}

impl<C: Cycle> Padding<C> {
    /// Computes the padding constants for an application whose challenge
    /// slots absorb `width` elements.
    pub fn new(params: &C::Params, width: usize) -> Result<Self> {
        use ragu_arithmetic::FixedGenerators;

        let host = C::host_generators(params).g()[0];
        Ok(Self {
            poly: crate::PolyCommitment::new(vec![C::CircuitField::ONE], host)?,
            host,
            sentinel: sentinel_element::<C>(params),
            challenge: if width == 0 {
                None
            } else {
                Some(padded_challenge::<C>(params, &[], width)?.1)
            },
        })
    }
}

