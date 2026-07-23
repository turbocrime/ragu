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
    /// evaluates to `y` at the point `x`.
    ///
    /// This is the *succinct* claim path: the polynomial stays out of the
    /// circuit, and enforcement is **recursive**. The claim wires occupy one
    /// of the circuit's [`NUM_POLY_QUERY_SLOTS`](crate::NUM_POLY_QUERY_SLOTS)
    /// instance slots, binding them to the circuit's $k(Y)$; when the
    /// resulting proof is fused as a child, the parent folds the quotient
    /// $(p(X) - y)/(X - x)$ into $f(X)$ and the polynomial (with its host
    /// commitment) into the PCS $(P, u, v)$ accumulator, and its `compute_v`
    /// circuit re-derives the matching terms from the instance-bound claim
    /// data. A root proof's own claims — not yet folded by a parent — are
    /// checked natively by [`Application::verify`](crate::Application::verify)
    /// against the carried claim polynomials.
    ///
    /// The fuse raising the claim also pre-checks it natively, so an honest
    /// prover with a dishonest witness fails early with `InvalidWitness`.
    /// That pre-check carries no soundness weight (it runs on the prover);
    /// enforcement never relies on prover behavior.
    ///
    /// A step body may call this at most `NUM_POLY_QUERY_SLOTS` times, and the
    /// call count must not depend on witness values (it is circuit structure).
    /// For claims over polynomials small enough to evaluate in-circuit,
    /// [`oracle::WitnessedPolynomial`](crate::oracle::WitnessedPolynomial)
    /// remains available as the fully in-circuit alternative.
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
