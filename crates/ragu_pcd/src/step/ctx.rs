//! Context object threaded through [`Step::witness`](super::Step::witness).
//!
//! Bundles the framework-side state — the [`Driver`] and the
//! [`FrameworkHooks`] container — so reusable sub-components called from a
//! step body take a single `&mut StepCtx`.

use alloc::vec::Vec;

use ragu_arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
};
use ragu_primitives::{Element, GadgetExt as _, io::Write};

use crate::{
    framework_hooks::FrameworkHooks,
    poly_commitment::{PolyCommitment, PolyHandle},
};

/// Framework-side state threaded through [`Step::witness`](super::Step::witness).
pub struct StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
{
    /// The underlying driver, for allocation and constraint emission.
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

    /// Witnesses this step's polynomials in-circuit in a single call,
    /// producing one [`PolyHandle`] per [`PolyCommitment`], in argument
    /// order. Each handle is two coordinate instance wires — the host
    /// commitment's embedded affine coordinates — and is itself a writable
    /// gadget over exactly those wires.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`](ragu_core::Error::InvalidWitness) if
    /// called more than once, or if `N` exceeds the application's polynomial
    /// capacity.
    pub fn witness_polynomial<const N: usize>(
        &mut self,
        commitments: [DriverValue<D, PolyCommitment<C>>; N],
    ) -> Result<[PolyHandle<'dr, D, C>; N]> {
        self.hooks.witness_polynomials(self.dr, commitments)
    }

    /// Records a poly-query claim: the polynomial behind `commitment`
    /// evaluates to `y` at `x`. The **parent** fuse enforces it (see
    /// [`framework_hooks`](crate::framework_hooks) for the binding chain).
    /// A repeat opening costs one claim slot and no polynomial slot.
    pub fn enforce_poly_query(
        &mut self,
        commitment: &PolyHandle<'dr, D, C>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        self.hooks.enforce_poly_query(commitment.coords(), x, y)
    }

    /// Derives a sound Fiat–Shamir challenge, `Hash(inputs)`, from `input` —
    /// any writable gadget, absorbed as the elements its [`Write`] emits, in
    /// write order: at most `challenge_width` of them, empty positions taking
    /// a fixed sentinel (see [`framework_hooks`](crate::framework_hooks)).
    ///
    /// **The caller's obligation**: the framework binds the challenge to
    /// these elements, not the elements to anything. Every element the gadget
    /// writes must be one this step has pinned (e.g. a [`PolyHandle`]'s
    /// coords) — a freely witnessed input lets the prover grind the challenge.
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
