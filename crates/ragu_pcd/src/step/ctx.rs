//! Context object threaded through [`Step::witness`](super::Step::witness).
//!
//! Bundles the framework-side state — the [`Driver`] and the
//! [`FrameworkHooks`] container — so that reusable sub-components called from a
//! step body can take a single `&mut StepCtx` rather than juggling individual
//! arguments. The three hooks are exposed as
//! [`witness_polynomial`](StepCtx::witness_polynomial),
//! [`enforce_poly_query`](StepCtx::enforce_poly_query) and
//! [`derive_challenge`](StepCtx::derive_challenge). New framework hooks added in
//! the future (e.g. transcript threading) belong on [`FrameworkHooks`] as well.

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};
use ragu_primitives::Element;

use crate::{
    framework_hooks::FrameworkHooks,
    poly_commitment::{PolyCommitment, PolyHandle},
};

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
    hooks: &'a mut FrameworkHooks<'dr, D, C>,
}

impl<'a, 'dr, D, C> StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
{
    pub(crate) fn new(dr: &'a mut D, hooks: &'a mut FrameworkHooks<'dr, D, C>) -> Self {
        Self { dr, hooks }
    }

    /// Witnesses this step's polynomials in-circuit, producing one
    /// [`PolyHandle`] per [`PolyCommitment`].
    ///
    /// The polynomial is handled **abstractly, by its commitment**: what is
    /// allocated is the two coordinate instance wires — the host commitment's
    /// affine coordinates, canonically embedded — and the coefficients ride
    /// along as a [`DriverValue`] — prover-side data, absent on a verifying
    /// driver — so witnessing costs two allocations regardless of the
    /// polynomial's size. Anything added here must preserve that: allocate
    /// the commitment's coordinates, retain the coefficients as a value.
    ///
    /// The commitment is reachable via [`PolyHandle::coords`] for challenges,
    /// hashing and the like; the retained polynomial is what a later
    /// [`enforce_poly_query`](Self::enforce_poly_query) opens. A
    /// [`PolyCommitment`] can only come from
    /// [`Application::commit_polynomial`](crate::Application::commit_polynomial),
    /// which derives the commitment from the polynomial.
    ///
    /// A step witnesses *all* its polynomials in a single call, and the
    /// handles come back in the same order: slot `i` is index `i`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`](ragu_core::Error::InvalidWitness) if
    /// called more than once, or if `N` exceeds the application's polynomial
    /// capacity.
    pub fn witness_polynomial<R: Rank, const N: usize>(
        &mut self,
        commitments: [DriverValue<D, PolyCommitment<C, R>>; N],
    ) -> Result<[PolyHandle<'dr, D, C, R>; N]> {
        self.hooks.witness_polynomials(self.dr, commitments)
    }

    /// Records a poly-query claim: the polynomial behind `commitment` evaluates
    /// to `y` at the point `x`.
    ///
    /// `commitment` is a [`PolyHandle`] from
    /// [`witness_polynomial`](Self::witness_polynomial); it carries both the
    /// in-circuit commitment and the polynomial, so the two cannot drift apart.
    ///
    /// This is the *succinct* claim path: the polynomial stays out of the
    /// circuit, and enforcement is **recursive**. The claim wires occupy one
    /// of the circuit's claim instance slots, binding them to the circuit's $k(Y)$; when the
    /// resulting proof is fused as a child, the parent folds the quotient
    /// $(p(X) - y)/(X - x)$ into $f(X)$ and the polynomial (with its host
    /// commitment) into the PCS $(P, u, v)$ accumulator, and its `compute_v`
    /// circuit re-derives the matching terms from the instance-bound claim
    /// data. A root proof's own claims — not yet folded by a parent — are
    /// checked natively by [`Application::verify`](crate::Application::verify)
    /// against the carried claim polynomials.
    ///
    /// The fuse raising the claim also pre-checks it natively, so an honest
    /// prover with a dishonest witness fails early with `InvalidWitness`;
    /// that pre-check runs on the prover and carries no soundness weight.
    ///
    /// Claims may be raised in any order, and the **same handle may be used
    /// more than once**: a claim names the polynomial it opens by the
    /// polynomial's embedded host coordinates — the very wires the handle
    /// holds — so a repeat opening costs one claim slot and no polynomial
    /// slot.
    ///
    /// # Soundness status
    ///
    /// A claim's name is bound through the accumulator: the coordinate wires
    /// are folded into the circuit's $k(Y)$, the parent's `compute_v`
    /// re-derives the claim-coordinate polynomial's $q(u)$ from them, and
    /// `(q, C_q)` rides the PCS accumulator — so a claim inherits exactly the
    /// framework's own guarantees, including the framework-wide deferred PCS
    /// opening; a **root** proof's own claims are checked natively by
    /// [`Application::verify`](crate::Application::verify). See
    /// [`framework_hooks`](crate::framework_hooks) for the chain.
    pub fn enforce_poly_query<R: Rank>(
        &mut self,
        commitment: &PolyHandle<'dr, D, C, R>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        self.hooks.enforce_poly_query(commitment.coords(), x, y)
    }

    /// Derives a sound Fiat–Shamir challenge from `inputs`.
    ///
    /// The challenge is `Hash(inputs)`, hashed natively and witnessed here;
    /// the inputs and the challenge go into the circuit's instance, and the
    /// parent's `challenge_binding` circuit re-derives the challenge from the
    /// inputs. **The step spends no Poseidon permutation and no committed
    /// stage** — the derivation is paid out of the framework's own budget,
    /// once per `(child, slot)`.
    ///
    /// At most
    /// [`ChallengeLayout::width`](crate::framework_hooks::ChallengeLayout::width)
    /// elements; the remaining positions are filled with a fixed sentinel so
    /// the sponge's shape is the same for every slot.
    ///
    /// # The caller's obligation
    ///
    /// The framework guarantees only that the challenge is the hash of *these
    /// elements*. Every input must be one this step has pinned — a
    /// [`PolyHandle::coords`](crate::poly_commitment::PolyHandle::coords)
    /// pair (the polynomial's commitment, so the standard poly-query
    /// Fiat–Shamir shape), header-carried data, or a wire otherwise
    /// constrained — since a freely witnessed input lets the prover grind the
    /// challenge by varying it. A pinned [`Point`](ragu_primitives::Point) is
    /// absorbable as its two coordinate wires.
    ///
    /// On a value-carrying driver the returned `Element` holds the real
    /// challenge immediately, so the step body can evaluate polynomials at it
    /// right away. Computing that value is why this hook — alone among the
    /// three — takes the cycle parameters: the hash needs the Poseidon
    /// constants at the moment the body wants the challenge. A step that
    /// derives challenges carries the parameters itself (its constructor
    /// already receives them for its own transcript work in practice); steps
    /// that don't never touch them.
    pub fn derive_challenge(
        &mut self,
        params: &C::Params,
        inputs: &[Element<'dr, D>],
    ) -> Result<Element<'dr, D>> {
        self.hooks.derive_challenge(self.dr, params, inputs)
    }
}
