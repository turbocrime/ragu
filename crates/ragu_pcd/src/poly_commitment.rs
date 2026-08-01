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
//!   it witnesses the representation as two coordinate wires (usable for
//!   challenges, hashing, cross-proof comparison) while retaining the
//!   polynomial, and is consumed by
//!   [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query).
//!
//! [`PolyCommitment::coords`] and [`PolyHandle::coords`] produce **identical
//! values** for every proof the framework accepts — one representation, in
//! and out of circuit. That is the whole consumer contract: hash it, store
//! it, compare it; the host-curve point itself never crosses this API.

use alloc::vec::Vec;

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{Element, io::Write};

/// A polynomial together with its commitment's representation.
///
/// Produced by
/// [`Application::commit_polynomial`](crate::Application::commit_polynomial),
/// which derives the representation from the polynomial. Thread this into a
/// [`Step`](crate::step::Step)'s witness and turn it into an in-circuit
/// [`PolyHandle`] with
/// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial).
pub struct PolyCommitment<C: Cycle, R: Rank> {
    polynomial: sparse::Polynomial<C::CircuitField, R>,
    coords: [C::CircuitField; 2],
}

impl<C: Cycle, R: Rank> Clone for PolyCommitment<C, R> {
    fn clone(&self) -> Self {
        Self {
            polynomial: self.polynomial.clone(),
            coords: self.coords,
        }
    }
}

impl<C: Cycle, R: Rank> PolyCommitment<C, R> {
    /// Bundles a polynomial with the representation of `host`, its host-curve
    /// commitment.
    ///
    /// The one site where canonicity is established: the embedding rejects
    /// the identity and any coordinate at or above $2^{254}$, so every
    /// constructed value has exactly one representation and
    /// [`coords`](Self::coords) is infallible.
    pub(crate) fn new(
        polynomial: sparse::Polynomial<C::CircuitField, R>,
        host: C::HostCurve,
    ) -> Result<Self> {
        let coords = crate::internal::challenge::host_coords::<C>(host)?;
        Ok(Self { polynomial, coords })
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
        polynomial: sparse::Polynomial<C::CircuitField, R>,
        host: C::HostCurve,
    ) -> Result<Self> {
        Self::new(polynomial, host)
    }

    /// Consumes the bundle, returning the polynomial.
    pub(crate) fn into_polynomial(self) -> sparse::Polynomial<C::CircuitField, R> {
        self.polynomial
    }
}

/// The in-circuit form of a [`PolyCommitment`]: the commitment's
/// representation as two coordinate wires, plus the retained polynomial for
/// the claim.
///
/// Created by
/// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial).
/// Use [`coords`](Self::coords) wherever the commitment is needed (deriving a
/// challenge, hashing into a header, comparing across proofs), and pass the
/// handle to
/// [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query)
/// to raise the claim.
///
/// A host-curve point is unrepresentable as a
/// [`Point`](ragu_primitives::Point) in a step — `Point` requires the curve's
/// base field to be the circuit's field, and `HostCurve::Base` is the *scalar*
/// field — but its affine coordinates, canonically bounded below $2^{254}$,
/// each fit one circuit-field element. The embedding is injective, so the
/// pair *is* the commitment, in the only form a step can hold.
///
/// The handle is a gadget, and plays for the cross-field commitment the role
/// [`Point`](ragu_primitives::Point) plays for a same-field one: its
/// [`Write`] emits exactly the two coordinate wires, so absorbing the handle —
/// into [`derive_challenge`](crate::step::StepCtx::derive_challenge), a
/// header sponge, or any other buffer — absorbs the commitment. The retained
/// polynomial is prover-only data and is never written.
#[derive(Gadget, Write)]
pub struct PolyHandle<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, R: Rank> {
    #[ragu(skip)]
    #[ragu(value)]
    polynomial: DriverValue<D, sparse::Polynomial<D::F, R>>,
    /// The slot's two coordinate instance wires: the commitment's
    /// representation.
    #[ragu(gadget)]
    coords: [Element<'dr, D>; 2],
    #[ragu(phantom)]
    _cycle: core::marker::PhantomData<C>,
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, R: Rank> PolyHandle<'dr, D, C, R> {
    /// Bundles a witnessed representation with its retained polynomial.
    pub(crate) fn new(
        polynomial: DriverValue<D, sparse::Polynomial<D::F, R>>,
        coords: [Element<'dr, D>; 2],
    ) -> Self {
        Self {
            polynomial,
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

    /// The retained polynomial (prover-only), e.g. to compute the evaluation
    /// `y = p(x)` that the claim asserts.
    pub fn polynomial(&self) -> &DriverValue<D, sparse::Polynomial<D::F, R>> {
        &self.polynomial
    }

    /// The polynomial's coefficients (little-endian), for the claim.
    pub(crate) fn coefficients(&self) -> DriverValue<D, Vec<D::F>> {
        self.polynomial
            .as_ref()
            .map(|p| p.iter_coeffs().collect::<Vec<_>>())
    }
}
