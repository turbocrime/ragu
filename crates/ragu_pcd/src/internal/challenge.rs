//! The poly-query commitment scheme: Pedersen-commit a polynomial on the host
//! curve and bridge the resulting point onto the nested curve so it can be
//! witnessed in-circuit. Also the native side of challenge derivation: hashing
//! the points a step supplies into the challenge they derive.

use alloc::vec;

use ragu_arithmetic::{CurveAffine, Cycle, ff::Field};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Result;

/// The framework polynomial `q` for a proof's recorded claim hosts: per slot,
/// the two [`host_coords`](crate::PolyCommitment::host_coords) of the host
/// commitment, slot-major. Deterministic from the recorded hosts, so it is
/// rebuilt rather than carried; empty at `POLYS = 0`.
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
/// zeroth nested generator's `x` coordinate. A slot's sponge always absorbs a
/// full challenge width, so prover, root verifier, and the `challenge_binding`
/// circuit agree on the sponge's shape by construction.
fn sentinel_element<C: Cycle>(params: &C::Params) -> C::CircuitField {
    use ragu_arithmetic::FixedGenerators;

    *C::nested_generators(params).g()[0]
        .coordinates()
        .expect("a fixed generator is not the identity")
        .x()
}

/// Pads a challenge slot's inputs to its full complement with the sentinel
/// and hashes them into the challenge they derive — the native counterpart of
/// what the `challenge_binding` circuit enforces; the two must agree exactly.
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

/// The per-application constants that pad a step's unused hook slots,
/// computed once at [`finalize`](crate::ApplicationBuilder::finalize) and
/// supplied to every proof as ordinary witness data. See `finish_slots` in
/// `framework_hooks` for the padding rationale.
pub(crate) struct Padding<C: Cycle> {
    /// The padding claim's committed polynomial: the constant $1$ (host
    /// commitment `g[0]`).
    pub poly: crate::PolyCommitment<C>,
    /// The fixed element filling an unfilled challenge-input position.
    pub sentinel: C::CircuitField,
    /// The challenge an all-sentinel slot derives. `None` at width zero,
    /// where there is nothing to hash.
    pub challenge: Option<C::CircuitField>,
}

impl<C: Cycle> Clone for Padding<C> {
    fn clone(&self) -> Self {
        Self {
            poly: self.poly.clone(),
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
            sentinel: sentinel_element::<C>(params),
            challenge: if width == 0 {
                None
            } else {
                Some(padded_challenge::<C>(params, &[], width)?.1)
            },
        })
    }
}
