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
//! * [`PolyQueryHandle`] is the in-circuit form, created by
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
/// [`PolyQueryHandle`] with
/// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial).
pub struct PolyCommitment<C: Cycle, R: Rank> {
    polynomial: sparse::Polynomial<C::CircuitField, R>,
    com: C::NestedCurve,
}

impl<C: Cycle, R: Rank> Clone for PolyCommitment<C, R> {
    fn clone(&self) -> Self {
        Self {
            polynomial: self.polynomial.clone(),
            com: self.com,
        }
    }
}

impl<C: Cycle, R: Rank> PolyCommitment<C, R> {
    /// Bundles a polynomial with the commitment derived from it.
    pub(crate) fn new(polynomial: sparse::Polynomial<C::CircuitField, R>, com: C::NestedCurve) -> Self {
        Self { polynomial, com }
    }

    /// The nested-curve commitment to the polynomial.
    pub fn commitment(&self) -> C::NestedCurve {
        self.com
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
        com: C::NestedCurve,
    ) -> Self {
        Self { polynomial, com }
    }

    /// Consumes the bundle, returning the polynomial.
    pub(crate) fn into_polynomial(self) -> sparse::Polynomial<C::CircuitField, R> {
        self.polynomial
    }
}

/// The in-circuit form of a [`PolyCommitment`]: the commitment allocated as a
/// [`Point`], plus the retained polynomial for the claim.
///
/// Created by
/// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial).
/// Use [`commitment`](Self::commitment) wherever the commitment point is needed
/// (deriving a challenge, hashing into a header), and pass the handle to
/// [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) to
/// raise the claim.
pub struct PolyQueryHandle<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, R: Rank> {
    com: Point<'dr, D, C::NestedCurve>,
    polynomial: DriverValue<D, sparse::Polynomial<D::F, R>>,
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, R: Rank> PolyQueryHandle<'dr, D, C, R> {
    /// Bundles an allocated commitment point with its retained polynomial.
    pub(crate) fn new(
        com: Point<'dr, D, C::NestedCurve>,
        polynomial: DriverValue<D, sparse::Polynomial<D::F, R>>,
    ) -> Self {
        Self { com, polynomial }
    }

    /// The in-circuit commitment point, for use in challenges, hashing, etc.
    pub fn commitment(&self) -> &Point<'dr, D, C::NestedCurve> {
        &self.com
    }

    /// The retained polynomial (prover-only), e.g. to compute the evaluation
    /// `y = p(x)` that the claim asserts.
    pub fn polynomial(&self) -> &DriverValue<D, sparse::Polynomial<D::F, R>> {
        &self.polynomial
    }

    /// A clone of the commitment point (for the claim wires).
    pub(crate) fn com(&self) -> Point<'dr, D, C::NestedCurve> {
        self.com.clone()
    }

    /// The polynomial's coefficients (little-endian), for the claim.
    pub(crate) fn coefficients(&self) -> DriverValue<D, Vec<D::F>> {
        self.polynomial
            .as_ref()
            .map(|p| p.iter_coeffs().collect::<Vec<_>>())
    }
}
