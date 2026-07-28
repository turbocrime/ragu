//! Per-challenge stages of an application circuit.
//!
//! A Fiat–Shamir challenge must be bound to the values it is derived from.
//! Hashing those values in-circuit does that directly, but costs one Poseidon
//! permutation per four of them — 288 application gates each — which the step's
//! ~2048-gate budget cannot absorb for anything but the narrowest inputs.
//!
//! Staging moves the cost out. The challenge input occupies a **stage** of the
//! application circuit: a partial trace at statically-known wire positions that
//! the prover commits *before* the rest of the witness exists. The challenge is
//! then the hash of that commitment, computed natively and witnessed, and the
//! parent binds it by re-deriving it from the same commitment. The application
//! circuit spends [`CHALLENGE_WIDTH`] wires and no
//! permutations, so the cost stops scaling with the input's width.
//!
//! Each slot gets its own stage — and therefore its own commitment — because a
//! challenge must be bound to the values known *at the point it is derived*.
//! One stage covering every slot would let a later slot's inputs influence an
//! earlier slot's challenge, which is exactly what Fiat–Shamir forbids.
//!
//! The slots form an induced **run**: one typed stage ([`Run`]) spans every
//! slot's wires, and the value-level [`layout`] says where the slot boundaries
//! fall inside that span — the same shape as the nested
//! [`challenge_bridge`](crate::internal::nested::stages::challenge_bridge)
//! family. The slot count is a property of the application, not of any Rust
//! type, so the geometry travels as data; [`Slot`] supplies only the per-slot
//! witness body.
//!
//! # Wire discipline
//!
//! A stage commits *all* of its wires, so every wire it holds must be pinned.
//! [`StepCtx::derive_challenge`](crate::step::StepCtx::derive_challenge)
//! constrains each stage wire that carries an input to equal the caller's
//! element, and each remaining wire to zero. Leaving the padding unconstrained
//! would let a prover vary it, and with it the commitment and the challenge —
//! challenge grinding, in exchange for no work at all.

use core::marker::PhantomData;

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::{
    polynomials::Rank,
    staging::{InducedGuard, InducedStages},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    allocator::Standard,
    vec::{ConstLen, FixedVec},
};

use crate::{CHALLENGE_WIDTH, NUM_CHALLENGE_SLOTS, framework_hooks::ProofValues};

/// A challenge stage's witness: the input elements, zero-padded to
/// [`CHALLENGE_WIDTH`].
pub struct Witness<F> {
    pub inputs: [F; CHALLENGE_WIDTH],
}

impl<F: Field> Default for Witness<F> {
    fn default() -> Self {
        Self {
            inputs: [F::ZERO; CHALLENGE_WIDTH],
        }
    }
}

/// The layout subdividing the challenge run into its slots: one
/// [`CHALLENGE_WIDTH`]-wire slot per challenge, anchored at the start of the
/// application circuit's trace ([`Run`]'s `Parent` is `()`).
///
/// This is the only place the run's geometry is described twice — once as
/// [`Run`]'s own `values()`, once as the slot widths here — and
/// [`configure_induced`](ragu_circuits::staging::StageBuilder::configure_induced)
/// rejects the pair if they disagree.
pub(crate) fn layout() -> InducedStages {
    InducedStages::new(alloc::vec![CHALLENGE_WIDTH; NUM_CHALLENGE_SLOTS])
}

/// One challenge slot's witness body: [`CHALLENGE_WIDTH`] committed wires.
///
/// Its chain position is unused — where a slot's wires land comes from
/// [`layout`], not from this type. One concrete type serves every slot of the
/// run.
pub struct Slot<F, R> {
    _marker: PhantomData<(F, R)>,
}

impl<F, R> Clone for Slot<F, R> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<F, R> Default for Slot<F, R> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<F: Field, R: Rank> ragu_circuits::staging::Stage<F, R> for Slot<F, R> {
    type Parent = ();
    type Witness<'source> = Witness<F>;
    type OutputKind = Kind![F; FixedVec<Element<'_, _>, ConstLen<CHALLENGE_WIDTH>>];

    fn values() -> usize {
        CHALLENGE_WIDTH
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let mut wires = alloc::vec::Vec::with_capacity(CHALLENGE_WIDTH);
        for i in 0..CHALLENGE_WIDTH {
            let value = witness.as_ref().map(move |w| w.inputs[i]);
            wires.push(Element::alloc(dr, allocator, value)?);
        }
        FixedVec::try_from(wires)
    }
}

/// The whole family of challenge slots as one typed stage — an application
/// circuit's [`MultiStageCircuit::Last`](ragu_circuits::staging::MultiStageCircuit::Last).
///
/// The run spans every slot's wires; [`layout`] subdivides it. Everything
/// after the run — the circuit's final trace — chains onto `Run` and computes
/// the same `skip_gates` it always did, with no knowledge that the span is
/// subdivided (`ragu_circuits`' `induced_run_matches_typed_chain` test pins
/// that equivalence). The run is never witnessed through the typed path — each
/// slot is reserved and filled individually via
/// [`configure_induced`](ragu_circuits::staging::StageBuilder::configure_induced)
/// — so its output is `()`.
pub struct Run<F, R> {
    _marker: PhantomData<(F, R)>,
}

impl<F, R> Default for Run<F, R> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<F: Field, R: Rank> ragu_circuits::staging::Stage<F, R> for Run<F, R> {
    type Parent = ();
    type Witness<'source> = ();
    type OutputKind = ();

    fn values() -> usize {
        NUM_CHALLENGE_SLOTS * CHALLENGE_WIDTH
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(())
    }
}

/// A slot's stage rx, built from its input values. The slot's generator
/// positions come from [`layout`]; the witness body is [`Slot`].
pub(crate) fn stage_rx<F: Field, R: Rank>(
    slot: usize,
    alpha: F,
    inputs: [F; CHALLENGE_WIDTH],
) -> Result<ragu_circuits::polynomials::sparse::Polynomial<F, R>> {
    layout().rx_configured(slot, alpha, &Slot::<F, R>::default(), Witness { inputs })
}

/// The challenge slots' reserved wires, with the run bookkeeping erased.
///
/// The [`StageBuilder`](ragu_circuits::staging::StageBuilder) reserves every
/// slot's wires before the step body runs. The guards carry no data beyond
/// those wires, so the adapter keeps them in a [`Slots`] on its own frame and
/// lends the hook this cursor over them.
///
/// Borrowed rather than owned on purpose: an owned `Box<dyn …>` would have to
/// outlive `'dr`, which would require `D: 'dr` at every `Circuit::witness`.
/// A borrow only needs `D` to outlive the loan, which the `StageBuilder`
/// parameter already implies.
pub(crate) trait ChallengeSlots<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    /// Fills the next unused slot with `inputs`, returning its wires and the
    /// values derived from its commitment: the bridged stage commitment and the
    /// challenge hashed from it.
    ///
    /// The caller must have taken a slot from
    /// [`FrameworkHooks::take_challenge_slot`](crate::framework_hooks::FrameworkHooks)
    /// first, which is what bounds the slot index — so running past the last
    /// slot is unreachable rather than an error case.
    ///
    /// The derivation lives here because it needs the rank — to build the stage
    /// polynomial — and this is the last place that knows it. Erasing the rank
    /// at this boundary is what keeps `R` out of every `Step::witness`.
    fn fill_next(
        &mut self,
        dr: &mut D,
        proof_values: DriverValue<D, ProofValues<'dr, C>>,
        inputs: DriverValue<D, [D::F; CHALLENGE_WIDTH]>,
    ) -> Result<Filled<'dr, D, C>>;
}

/// What [`ChallengeSlots::fill_next`] produces for one slot.
pub(crate) struct Filled<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    /// The stage's reserved wires, carrying the input values.
    pub wires: FixedVec<Element<'dr, D>, ConstLen<CHALLENGE_WIDTH>>,
    /// The bridged stage commitment and the challenge hashed from it.
    pub derived: DriverValue<D, (C::NestedCurve, D::F)>,
}

/// The adapter-owned store the [`ChallengeSlots`] cursor lends out. This is
/// where `R` lives — and where it stays: the step body never names it.
pub(crate) struct Slots<'dr, D: Driver<'dr>, R: Rank> {
    guards: alloc::vec::Vec<Option<InducedGuard<'dr, D, R, Slot<D::F, R>>>>,
    next: usize,
}

impl<'dr, D: Driver<'dr>, R: Rank> Slots<'dr, D, R> {
    /// Wraps the guards of one reserved run, in slot order.
    pub(crate) fn new(guards: alloc::vec::Vec<InducedGuard<'dr, D, R, Slot<D::F, R>>>) -> Self {
        Self {
            guards: guards.into_iter().map(Some).collect(),
            next: 0,
        }
    }
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, R: Rank> ChallengeSlots<'dr, D, C>
    for Slots<'dr, D, R>
{
    fn fill_next(
        &mut self,
        dr: &mut D,
        proof_values: DriverValue<D, ProofValues<'dr, C>>,
        inputs: DriverValue<D, [D::F; CHALLENGE_WIDTH]>,
    ) -> Result<Filled<'dr, D, C>> {
        let slot = self.next;
        let witness = inputs.as_ref().map(|inputs| Witness { inputs: *inputs });

        // `unenforced`: the wires carry no invariant of their own. The caller
        // constrains every one of them — inputs to its elements, padding to
        // zero — immediately after this returns.
        //
        // Each guard is taken at most once and the slot index is bounded by
        // `take_challenge_slot`, so no slot below can be reached twice.
        let taken = self
            .guards
            .get_mut(slot)
            .and_then(|guard| guard.take())
            .map(|guard| guard.unenforced(dr, witness));
        let wires =
            taken.unwrap_or_else(|| unreachable!("slot is bounded by NUM_CHALLENGE_SLOTS"))?;
        self.next += 1;

        let derived = D::try_just(|| {
            let proof_values = proof_values.take();
            crate::internal::challenge::staged_challenge::<C, R>(
                proof_values.params,
                slot,
                proof_values.challenge_alpha,
                proof_values.bridge_alpha,
                inputs.take(),
            )
        })?;

        Ok(Filled { wires, derived })
    }
}

#[cfg(test)]
mod tests {
    use ragu_circuits::staging::{Stage, StageExt};
    use ragu_pasta::Fp;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    #[test]
    fn slot_body_matches_width() {
        assert_stage_values(&Slot::<Fp, R>::default());
    }

    /// The layout tiles the [`Run`] exactly: same start gate, same end gate.
    /// `configure_induced` enforces this at reservation; pinning it here keeps
    /// the failure local if the two descriptions of the geometry drift.
    #[test]
    fn layout_tiles_run() {
        let layout = layout();
        assert_eq!(layout.len(), NUM_CHALLENGE_SLOTS);
        assert_eq!(
            layout.skip_gates(0),
            <Run<Fp, R> as Stage<Fp, R>>::skip_gates()
        );
        assert_eq!(
            layout.final_skip_gates(),
            <Run<Fp, R> as Stage<Fp, R>>::skip_gates()
                + <Run<Fp, R> as StageExt<Fp, R>>::num_gates()
        );
    }
}
