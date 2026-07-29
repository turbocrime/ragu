//! Handles that bundle a polynomial with its poly-query commitment.
//!
//! The poly-query oracle needs two things that must not drift apart: the
//! polynomial (prover-only) and the nested-curve commitment to it (witnessed
//! in-circuit and recorded in the claim). Passing them to
//! [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) as separate
//! arguments let a step body supply a commitment for one polynomial and
//! coefficients for another. These two handles keep them together:
//!
//! * [`PolyCommitment`] is produced by
//!   [`Application::commit_polynomial`](crate::Application::commit_polynomial):
//!   the commitment is *derived from* the polynomial, so an honest caller
//!   cannot mismatch them.
//! * [`PolyHandle`] is the in-circuit form, created by
//!   [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial):
//!   it witnesses the commitment as a [`Point`] (usable for challenges,
//!   hashing, etc.) while retaining the polynomial, and is consumed by
//!   [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query).

use alloc::vec::Vec;

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::Point;

/// A polynomial together with its framework poly-query commitment.
///
/// Produced by
/// [`Application::commit_polynomial`](crate::Application::commit_polynomial),
/// which derives the commitment from the polynomial. Thread this into a
/// [`Step`](crate::step::Step)'s witness and turn it into an in-circuit
/// [`PolyHandle`] with
/// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial).
pub struct PolyCommitment<C: Cycle, R: Rank> {
    polynomial: sparse::Polynomial<C::CircuitField, R>,
    host: C::HostCurve,
}

impl<C: Cycle, R: Rank> Clone for PolyCommitment<C, R> {
    fn clone(&self) -> Self {
        Self {
            polynomial: self.polynomial.clone(),
            host: self.host,
        }
    }
}

impl<C: Cycle, R: Rank> PolyCommitment<C, R> {
    /// Bundles a polynomial with the host-curve commitment derived from it.
    pub(crate) fn new(
        polynomial: sparse::Polynomial<C::CircuitField, R>,
        host: C::HostCurve,
    ) -> Self {
        Self { polynomial, host }
    }

    /// The polynomial's host-curve commitment — `commit(polynomial)`, canonical
    /// for that polynomial. The nested-curve `bridge_com` a claim carries is
    /// derived from this by the framework, in
    /// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial),
    /// once the claim's slot is known.
    pub(crate) fn host(&self) -> C::HostCurve {
        self.host
    }

    /// Builds a handle whose commitment deliberately does **not** bind its
    /// polynomial, modelling a prover that patched
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
    ) -> Self {
        Self::new(polynomial, host)
    }

    /// Consumes the bundle, returning the polynomial.
    pub(crate) fn into_polynomial(self) -> sparse::Polynomial<C::CircuitField, R> {
        self.polynomial
    }
}

/// The in-circuit form of a [`PolyCommitment`]: the polynomial's **bridge**
/// commitment allocated as a [`Point`], plus the retained polynomial for the
/// claim.
///
/// Created by
/// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial).
/// Use [`bridge_commitment`](Self::bridge_commitment) wherever the point is
/// needed (deriving a challenge, hashing into a header), and pass the handle to
/// [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) to
/// raise the claim.
///
/// # Two commitments, and this is not the polynomial's
///
/// [`PolyCommitment`]'s host commitment is `commit(polynomial)` — the real
/// thing, on the host curve, canonical for that polynomial. It cannot be a
/// [`Point`] in a
/// step: `Point` requires the curve's base field to be the circuit's field, and
/// `HostCurve::Base` is the *scalar* field.
///
/// So what a step sees is `bridge_com`: the commitment of this claim's bridge
/// stage, whose wires *are* `host`'s coordinates, blinded by
/// `bridge_alpha^(5 + slot)`. It is a function of `(host, slot, bridge_alpha,
/// capacity)`, so the same polynomial in a different slot or a different proof
/// has a different `bridge_com`. It identifies a polynomial *within one proof*,
/// which is what a claim needs, and it is not homomorphic in the polynomial —
/// coordinates are not linear in the point.
pub struct PolyHandle<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, R: Rank> {
    bridge_com: Point<'dr, D, C::NestedCurve>,
    polynomial: DriverValue<D, sparse::Polynomial<D::F, R>>,
    slot: usize,
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, R: Rank> PolyHandle<'dr, D, C, R> {
    /// Bundles an allocated bridge commitment with its retained polynomial.
    pub(crate) fn new(
        bridge_com: Point<'dr, D, C::NestedCurve>,
        polynomial: DriverValue<D, sparse::Polynomial<D::F, R>>,
        slot: usize,
    ) -> Self {
        Self {
            bridge_com,
            polynomial,
            slot,
        }
    }

    /// The claim slot this handle was assigned when it was witnessed. Fixes
    /// which bridge stage — and therefore which generators — `bridge_com`
    /// commits to, so the claim must occupy this instance slot too.
    pub(crate) fn slot(&self) -> usize {
        self.slot
    }

    /// The in-circuit bridge commitment, for use in challenges, hashing, etc.
    pub fn bridge_commitment(&self) -> &Point<'dr, D, C::NestedCurve> {
        &self.bridge_com
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
