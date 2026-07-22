//! Context object threaded through [`Step::witness`](super::Step::witness).
//!
//! Bundles the framework-side state — the [`Driver`], the [`FrameworkHooks`]
//! container, and the cycle's Poseidon parameters — so that reusable
//! sub-components called from a step body can take a single `&mut StepCtx`
//! rather than juggling individual arguments. The poly-query claim sink is
//! exposed via [`enforce_poly_query`](StepCtx::enforce_poly_query) and the
//! challenge hook via [`derive_challenge`](StepCtx::derive_challenge). New
//! framework hooks added in the future (e.g. transcript threading) belong on
//! [`FrameworkHooks`] as well.

use alloc::vec::Vec;

use ragu_arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};
use ragu_primitives::{Element, Point};

use crate::framework_hooks::{ChallengeInput, FrameworkHooks};

/// Framework-side state threaded through [`Step::witness`](super::Step::witness).
/// The poly-query claim sink is exposed via
/// [`enforce_poly_query`](Self::enforce_poly_query) and sound Fiat–Shamir
/// challenges via [`derive_challenge`](Self::derive_challenge).
pub struct StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
{
    /// The underlying driver. Components called from a step body use this for
    /// allocation and constraint emission.
    pub dr: &'a mut D,
    hooks: &'a mut FrameworkHooks<'dr, D, C::NestedCurve>,
    poseidon: &'dr C::CircuitPoseidon,
}

impl<'a, 'dr, D, C> StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
{
    pub(crate) fn new(
        dr: &'a mut D,
        hooks: &'a mut FrameworkHooks<'dr, D, C::NestedCurve>,
        poseidon: &'dr C::CircuitPoseidon,
    ) -> Self {
        Self {
            dr,
            hooks,
            poseidon,
        }
    }

    /// The cycle's Poseidon parameters, for step bodies that hash in-circuit
    /// (e.g. via [`Sponge`](ragu_primitives::poseidon::Sponge) or the
    /// [`oracle`](crate::oracle) gadgets) without threading parameters through
    /// their own state.
    pub fn poseidon(&self) -> &'dr C::CircuitPoseidon {
        self.poseidon
    }

    /// Records a poly-query claim: the polynomial with the given
    /// `coefficients` (little-endian), committed to by `com` (a nested curve
    /// point — see
    /// [`Application::commit_polynomial`](crate::Application::commit_polynomial)),
    /// evaluates to `y` at the point `x`. The framework collects these via the
    /// adapter's `Aux` and enforces each of them natively at fuse time,
    /// rejecting the witness if the evaluation or the commitment binding does
    /// not hold.
    ///
    /// This is the *succinct* claim path: the polynomial stays out of the
    /// circuit. Its enforcement is native (prover-side) until the claims are
    /// folded into the proof system's $(P, u, v)$ accumulator; for claims that
    /// must be sound today, evaluate in-circuit with
    /// [`oracle::WitnessedPolynomial`](crate::oracle::WitnessedPolynomial)
    /// instead.
    pub fn enforce_poly_query(
        &mut self,
        com: Point<'dr, D, C::NestedCurve>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
        coefficients: DriverValue<D, Vec<D::F>>,
    ) -> Result<()> {
        self.hooks
            .enforce_polynomial_query(self.dr, com, x, y, coefficients)
    }

    /// Derives a sound Fiat–Shamir challenge from `input`: the in-circuit
    /// Poseidon sponge hash of the input's elements. The returned `Element`
    /// is constrained to equal that hash, and on a value-carrying driver it
    /// holds the real challenge value immediately, so the step body can
    /// evaluate polynomials at it right away.
    pub fn derive_challenge<G: ChallengeInput<'dr, D>>(
        &mut self,
        input: G,
    ) -> Result<Element<'dr, D>> {
        self.hooks.derive_challenge(self.dr, self.poseidon, input)
    }
}
