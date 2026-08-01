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

    /// Records a poly-query claim: the polynomial behind `commitment` (a
    /// [`PolyHandle`] from [`polys`](Self::polys)) evaluates to `y` at `x`.
    ///
    /// The polynomial stays out of the circuit: the claim occupies one of the
    /// circuit's claim instance slots, and the **parent** fuse enforces it
    /// through the PCS accumulator — a root proof's own claims are checked
    /// natively by [`Application::verify`](crate::Application::verify). See
    /// [`framework_hooks`](crate::framework_hooks) for the binding chain.
    /// The fuse raising the claim pre-checks it natively, so a dishonest
    /// witness fails early rather than producing an unfusable proof.
    ///
    /// The same handle may be opened more than once: a repeat opening costs
    /// one claim slot and no polynomial slot.
    pub fn enforce_poly_query(
        &mut self,
        commitment: &PolyHandle<'dr, D, C>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        self.hooks.enforce_poly_query(commitment.coords(), x, y)
    }

    /// Derives a sound Fiat–Shamir challenge from `input` — any writable
    /// gadget, absorbed as the elements its [`Write`] emits, in write order.
    ///
    /// The challenge is `Hash(inputs)`, hashed natively (which is why this
    /// hook takes the cycle parameters) and re-derived by the parent's
    /// `challenge_binding` circuit from the instance — the step itself spends
    /// no Poseidon permutation. At most
    /// [`HookLayout::challenge_width`](crate::framework_hooks::HookLayout::challenge_width)
    /// elements; empty positions take a fixed sentinel. On a value-carrying
    /// driver the returned `Element` holds the real value immediately.
    ///
    /// **The caller's obligation**: the framework binds the challenge to
    /// these elements, not the elements to anything. Every element the gadget
    /// writes must be one this step has pinned — a [`PolyHandle`],
    /// header-carried data, a wire otherwise constrained — since a freely
    /// witnessed input lets the prover grind the challenge by varying it.
    pub fn derive_challenge<G>(&mut self, params: &C::Params, input: &G) -> Result<Element<'dr, D>>
    where
        G: Gadget<'dr, D>,
        G::Kind: Write<D::F>,
    {
        let mut inputs = Vec::new();
        input.write(self.dr, &mut inputs)?;
        self.hooks.derive_challenge(self.dr, params, &inputs)
    }
}
