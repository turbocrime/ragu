//! Handles that bundle a polynomial with its poly-query commitment.
//!
//! The poly-query oracle needs two things that must not drift apart: the
//! polynomial (prover-only) and its commitment's **representation** — the
//! host commitment's affine coordinates, canonically embedded in the circuit
//! field. Passing them to
//! [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) as
//! separate arguments would let a step body supply a representation for one
//! polynomial and coefficients for another. These two handles keep them
//! together:
//!
//! * [`PolyCommitment`] is the native form, produced by
//!   [`Application::commit_polynomial`](crate::Application::commit_polynomial):
//!   the representation is *derived from* the polynomial, so an honest caller
//!   cannot mismatch them.
//! * [`PolyHandle`] is the in-circuit form, created by
//!   [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial):
//!   the representation as two coordinate wires (usable for challenges,
//!   hashing, cross-proof comparison), consumed by
//!   [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query).
//!
//! [`PolyCommitment::coords`] and [`PolyHandle::coords`] produce **identical
//! values** for every proof the framework accepts — one representation, in
//! and out of circuit. That is the whole consumer contract: hash it, store
//! it, compare it; the host-curve point itself never crosses this API.

use alloc::vec::Vec;

use ragu_arithmetic::{
    CurveAffine, Cycle,
    ff::{Field, PrimeField},
};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{Element, io::Write};

/// Bits admitted in a coordinate's high half.
///
/// Two short of a limb's 128, which is what makes the decomposition canonical:
/// the largest value `lo + 2^128·hi` can then take is `2^254 - 1`, below both
/// Pasta moduli, so no coordinate has a wrapped second decomposition. The cost
/// is a completeness bound: a commitment with a coordinate at or above `2^254`
/// — a `~2^-129` fraction of the field — cannot be witnessed.
const HIGH_BITS: usize = 126;

/// The four 128-bit limbs `[x_lo, x_hi, y_lo, y_hi]` of a host commitment's
/// coordinates — the split of `to_repr()` into 16-byte halves that
/// [`PolyCommitment::host_coords`] recomposes into the commitment's
/// representation.
///
/// Errors rather than truncating when a coordinate does not fit: see
/// [`HIGH_BITS`], whose width bound is what makes the split — and therefore
/// the representation — canonical.
fn host_limbs<C: CurveAffine>(host: C) -> Result<[u128; 4]> {
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

/// `lo + 2^128·hi` in `F`. With `hi < 2^126` (the [`host_limbs`] bound) the
/// result is below `2^254 < |F|`, so no reduction occurs.
fn embed_coordinate<F: PrimeField>(lo: u128, hi: u128) -> F {
    let shift = F::from_u128(1 << 64).square();
    F::from_u128(lo) + shift * F::from_u128(hi)
}

/// A polynomial's coefficients together with its commitment's representation.
///
/// Produced by
/// [`Application::commit_polynomial`](crate::Application::commit_polynomial),
/// which derives the representation from the polynomial. Thread this into a
/// [`Step`](crate::step::Step)'s witness and turn it into an in-circuit
/// [`PolyHandle`] with
/// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial).
///
/// Coefficients are held rank-erased (little-endian `Vec`); the framework
/// re-ranks them where its rank is in scope.
pub struct PolyCommitment<C: Cycle> {
    coefficients: Vec<C::CircuitField>,
    coords: [C::CircuitField; 2],
}

impl<C: Cycle> Clone for PolyCommitment<C> {
    fn clone(&self) -> Self {
        Self {
            coefficients: self.coefficients.clone(),
            coords: self.coords,
        }
    }
}

impl<C: Cycle> PolyCommitment<C> {
    /// The host-curve commitment to a poly-query polynomial, rejecting the
    /// identity (which has no affine coordinates, so it could not be
    /// witnessed as a `Point` nor bridged).
    pub(crate) fn host_commitment<R: Rank>(
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

    /// A host commitment's affine coordinates, canonically embedded in the
    /// circuit field — one element per coordinate, `lo + 2^128·hi` over the
    /// limbs [`host_limbs`] splits (and bounds: a coordinate is below
    /// `2^254`, so the embedding is injective and every embedded value fits
    /// the circuit field).
    pub(crate) fn host_coords(host: C::HostCurve) -> Result<[C::CircuitField; 2]> {
        let [x_lo, x_hi, y_lo, y_hi] = host_limbs(host)?;
        Ok([
            embed_coordinate::<C::CircuitField>(x_lo, x_hi),
            embed_coordinate::<C::CircuitField>(y_lo, y_hi),
        ])
    }

    /// Bundles a polynomial's coefficients with the representation of `host`,
    /// its host-curve commitment.
    ///
    /// The one author-facing site where canonicity is established: the
    /// embedding rejects the identity and any coordinate at or above
    /// $2^{254}$, so every constructed value has exactly one representation
    /// and [`coords`](Self::coords) is infallible.
    pub(crate) fn new(coefficients: Vec<C::CircuitField>, host: C::HostCurve) -> Result<Self> {
        let coords = Self::host_coords(host)?;
        Ok(Self {
            coefficients,
            coords,
        })
    }

    /// Assembles a commitment from already-witnessed values — the drain path
    /// from a proved circuit's wires, where the fuse's pre-check (not this
    /// constructor) establishes that the coords bind the coefficients.
    pub(crate) fn from_parts(
        coefficients: Vec<C::CircuitField>,
        coords: [C::CircuitField; 2],
    ) -> Self {
        Self {
            coefficients,
            coords,
        }
    }

    /// The commitment's **representation**: the host commitment's affine
    /// coordinates, canonically embedded in the circuit field. Canonical for
    /// the polynomial and identical to what
    /// [`PolyHandle::coords`] exposes in-circuit — hash this for an anchor,
    /// store it, compare it.
    pub fn coords(&self) -> [C::CircuitField; 2] {
        self.coords
    }

    /// Builds a handle whose representation deliberately does **not** bind
    /// its polynomial, modelling a prover that patched
    /// [`Application::commit_polynomial`](crate::Application::commit_polynomial)
    /// out of the loop.
    ///
    /// The honest API makes this state unrepresentable; it exists only so
    /// tests can exercise the framework's own enforcement rather than the
    /// prover-side pre-check. Pair with
    /// [`ApplicationBuilder::skip_claim_precheck_for_testing`](crate::ApplicationBuilder::skip_claim_precheck_for_testing).
    #[cfg(feature = "unstable-fuzzing")]
    pub fn desync_for_testing(
        coefficients: Vec<C::CircuitField>,
        host: C::HostCurve,
    ) -> Result<Self> {
        Self::new(coefficients, host)
    }

    /// The polynomial's coefficients, little-endian.
    pub(crate) fn coefficients(&self) -> &[C::CircuitField] {
        &self.coefficients
    }

    /// Consumes the bundle, returning the coefficients.
    pub(crate) fn into_coefficients(self) -> Vec<C::CircuitField> {
        self.coefficients
    }
}

/// The in-circuit form of a [`PolyCommitment`]: the commitment's
/// representation as two coordinate wires, plus the retained coefficients
/// (prover-only) for the claim.
///
/// Created by
/// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial);
/// opened via
/// [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query).
///
/// A host-curve point cannot be a [`Point`](ragu_primitives::Point) in a step
/// (`Point` requires `Base = D::F`, and `HostCurve::Base` is the *scalar*
/// field), but its affine coordinates — canonically bounded below $2^{254}$ —
/// each fit one circuit-field element, injectively. So the pair *is* the
/// commitment, and the handle plays `Point`'s role for it: a writable gadget
/// whose [`Write`] emits exactly the two coordinate wires. Absorbing the
/// handle absorbs the commitment; the coefficients are never written.
#[derive(Gadget, Write)]
pub struct PolyHandle<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    #[ragu(skip)]
    #[ragu(value)]
    coefficients: DriverValue<D, Vec<D::F>>,
    /// The slot's two coordinate instance wires: the commitment's
    /// representation.
    #[ragu(gadget)]
    coords: [Element<'dr, D>; 2],
    #[ragu(phantom)]
    _cycle: core::marker::PhantomData<C>,
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> PolyHandle<'dr, D, C> {
    /// Bundles a witnessed representation with its retained coefficients.
    pub(crate) fn new(
        coefficients: DriverValue<D, Vec<D::F>>,
        coords: [Element<'dr, D>; 2],
    ) -> Self {
        Self {
            coefficients,
            coords,
            _cycle: core::marker::PhantomData,
        }
    }

    /// The polynomial's **canonical** in-circuit identity: its commitment's
    /// representation, as the slot's coordinate instance wires. The same for
    /// every proof that commits this polynomial, and identical to
    /// [`PolyCommitment::coords`] natively — so this is what a
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge) call
    /// absorbs, what an anchor hashes, and what cross-proof comparisons
    /// compare.
    pub fn coords(&self) -> [Element<'dr, D>; 2] {
        self.coords.clone()
    }

    /// Evaluates the retained polynomial at `x`, as a prover-only value.
    ///
    /// The one sanctioned use of the retained coefficients: a step allocates
    /// the result and claims it with
    /// [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) —
    /// which is what binds it. The coefficients themselves stay inaccessible
    /// to the step body: nothing in-circuit could bind them, so nothing may
    /// depend on them except through a claim.
    pub fn eval(&self, x: DriverValue<D, D::F>) -> DriverValue<D, D::F> {
        self.coefficients.as_ref().and_then(|coefficients| {
            x.map(|x| {
                coefficients
                    .iter()
                    .rev()
                    .fold(D::F::ZERO, |acc, coefficient| acc * x + coefficient)
            })
        })
    }

    /// The polynomial's coefficients (little-endian), for the claim.
    pub(crate) fn coefficients(&self) -> DriverValue<D, Vec<D::F>> {
        self.coefficients.clone()
    }
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
}
