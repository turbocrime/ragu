//! Context object threaded through [`Step::witness`](super::Step::witness).
//!
//! Bundles the framework-side state — the [`Driver`] and the
//! [`FrameworkHooks`] container — so that reusable sub-components called from a
//! step body can take a single `&mut StepCtx` rather than juggling individual
//! arguments. The hooks are exposed as [`polys`](StepCtx::polys),
//! [`enforce_poly_query`](StepCtx::enforce_poly_query) and
//! [`derive_challenge`](StepCtx::derive_challenge). New framework hooks added in
//! the future (e.g. transcript threading) belong on [`FrameworkHooks`] as well.

use alloc::vec::Vec;

use ragu_arithmetic::Cycle;
use ragu_core::{Result, drivers::Driver, gadgets::Gadget};
use ragu_primitives::{Element, GadgetExt as _, io::Write};

use crate::{framework_hooks::FrameworkHooks, poly_commitment::PolyHandle};

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

    /// The step's polynomial handles, one per slot in the application's
    /// declared capacity: the commitments
    /// [`Step::polynomials`](super::Step::polynomials) declared, in
    /// declaration order, then the padding polynomial in each remaining
    /// slot. All were witnessed by the framework before the body ran.
    ///
    /// The polynomial is handled **abstractly, by its commitment**: each
    /// handle is two coordinate instance wires — the host commitment's
    /// affine coordinates, canonically embedded — and the handle is itself a
    /// writable gadget over exactly those wires. Absorb it for challenges
    /// and hashing, compare via [`PolyHandle::coords`], evaluate via
    /// [`PolyHandle::eval`], and open it with
    /// [`enforce_poly_query`](Self::enforce_poly_query).
    pub fn polys(&self) -> Vec<PolyHandle<'dr, D, C>> {
        self.hooks.witnessed_polys().to_vec()
    }

    /// Records a poly-query claim: the polynomial behind `commitment` evaluates
    /// to `y` at the point `x`.
    ///
    /// `commitment` is a [`PolyHandle`] from [`polys`](Self::polys); it
    /// carries both the in-circuit commitment and the polynomial, so the two
    /// cannot drift apart.
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
    pub fn enforce_poly_query(
        &mut self,
        commitment: &PolyHandle<'dr, D, C>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        self.hooks.enforce_poly_query(commitment.coords(), x, y)
    }

    /// Derives a sound Fiat–Shamir challenge from `input`.
    ///
    /// `input` is any writable gadget, absorbed as the elements its
    /// [`Write`] emits, in write order: a [`PolyHandle`] is its commitment's
    /// two coordinate wires, a pinned [`Point`](ragu_primitives::Point) its
    /// two coordinates, and tuples and arrays absorb their parts in
    /// declaration order.
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
    /// elements*. Every element the gadget writes must be one this step has
    /// pinned — a [`PolyHandle`] (the polynomial's commitment, so the
    /// standard poly-query Fiat–Shamir shape), header-carried data, or a
    /// wire otherwise constrained — since a freely witnessed input lets the
    /// prover grind the challenge by varying it.
    ///
    /// On a value-carrying driver the returned `Element` holds the real
    /// challenge immediately, so the step body can evaluate polynomials at it
    /// right away. Computing that value is why this hook — alone among the
    /// three — takes the cycle parameters: the hash needs the Poseidon
    /// constants at the moment the body wants the challenge. A step that
    /// derives challenges carries the parameters itself (its constructor
    /// already receives them for its own transcript work in practice); steps
    /// that don't never touch them.
    pub fn derive_challenge<G>(
        &mut self,
        params: &C::Params,
        input: &G,
    ) -> Result<Element<'dr, D>>
    where
        G: Gadget<'dr, D>,
        G::Kind: Write<D::F>,
    {
        let mut inputs = Vec::new();
        input.write(self.dr, &mut inputs)?;
        self.hooks.derive_challenge(self.dr, params, &inputs)
    }
}
