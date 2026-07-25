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
//! The stages chain in slot order, so slot `i`'s wires occupy a distinct,
//! statically-known region of the trace. The chain is expressed through the
//! `Parent` associated type, which cannot be computed from a const generic on
//! stable Rust, so [`Stage`] takes its parent as a type parameter and each slot
//! is an alias — the same shape as the nested
//! [`host_bridge`](crate::internal::nested::stages::host_bridge) stages.
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
    staging::{StageExt, StageGuard},
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

use crate::CHALLENGE_WIDTH;

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

/// One challenge slot's stage — [`CHALLENGE_WIDTH`] committed wires — chained
/// after `P`.
pub struct Stage<F, R, P> {
    _marker: PhantomData<(F, R, P)>,
}

impl<F, R, P> Default for Stage<F, R, P> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<F: Field, R: Rank, P: ragu_circuits::staging::Stage<F, R>> ragu_circuits::staging::Stage<F, R>
    for Stage<F, R, P>
{
    type Parent = P;
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

/// Challenge stage for slot 0.
pub type Stage0<F, R> = Stage<F, R, ()>;
/// Challenge stage for slot 1.
pub type Stage1<F, R> = Stage<F, R, Stage0<F, R>>;

/// Compile-time guard: the number of aliases above must match the number of
/// challenge slots. Bump both together.
const _: () = assert!(crate::NUM_CHALLENGE_SLOTS == 2);

/// The last stage in the chain — an application circuit's
/// [`MultiStageCircuit::Last`](ragu_circuits::staging::MultiStageCircuit::Last).
pub type Last<F, R> = Stage1<F, R>;

/// A slot's stage rx, built from its input values. Dispatches on the slot
/// because each slot is a distinct type with distinct generator positions.
pub(crate) fn stage_rx<F: Field, R: Rank>(
    slot: usize,
    alpha: F,
    inputs: [F; CHALLENGE_WIDTH],
) -> Result<ragu_circuits::polynomials::sparse::Polynomial<F, R>> {
    let witness = Witness { inputs };
    match slot {
        0 => Stage0::<F, R>::rx(alpha, witness),
        1 => Stage1::<F, R>::rx(alpha, witness),
        _ => unreachable!("slot is bounded by NUM_CHALLENGE_SLOTS"),
    }
}

/// The challenge slots' reserved wires, with their concrete stage types
/// erased.
///
/// The [`StageBuilder`](ragu_circuits::staging::StageBuilder) reserves every
/// stage's wires before the step body runs, so the whole `Parent` chain is
/// resolved by then. The guards differ *only* in that chain — which
/// [`StageGuard::unenforced`] never consults, and which carries no data — so
/// the adapter keeps them in a [`Slots`] on its own frame and lends the hook
/// this cursor over them.
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
        params: Option<(&C::Params, C::ScalarField, C::CircuitField)>,
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
    slot0: Option<StageGuard<'dr, D, R, Stage0<D::F, R>>>,
    slot1: Option<StageGuard<'dr, D, R, Stage1<D::F, R>>>,
    next: usize,
}

impl<'dr, D: Driver<'dr>, R: Rank> Slots<'dr, D, R> {
    pub(crate) fn new(
        slot0: StageGuard<'dr, D, R, Stage0<D::F, R>>,
        slot1: StageGuard<'dr, D, R, Stage1<D::F, R>>,
    ) -> Self {
        Self {
            slot0: Some(slot0),
            slot1: Some(slot1),
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
        params: Option<(&C::Params, C::ScalarField, C::CircuitField)>,
        inputs: DriverValue<D, [D::F; CHALLENGE_WIDTH]>,
    ) -> Result<Filled<'dr, D, C>> {
        let slot = self.next;
        let witness = inputs.as_ref().map(|inputs| Witness { inputs: *inputs });

        // `unenforced`: the wires carry no invariant of their own. The caller
        // constrains every one of them — inputs to its elements, padding to
        // zero — immediately after this returns.
        //
        // Each guard is taken at most once and the slot index is bounded by
        // `take_challenge_slot`, so neither arm below can be reached twice.
        let taken = match slot {
            0 => self.slot0.take().map(|guard| guard.unenforced(dr, witness)),
            1 => self.slot1.take().map(|guard| guard.unenforced(dr, witness)),
            _ => None,
        };
        let wires =
            taken.unwrap_or_else(|| unreachable!("slot is bounded by NUM_CHALLENGE_SLOTS"))?;
        self.next += 1;

        let derived = D::try_just(|| {
            let (params, bridge_alpha, challenge_alpha) = params.ok_or_else(|| {
                ragu_core::Error::Initialization(
                    "derive_challenge requires the proving adapter".into(),
                )
            })?;
            crate::internal::challenge::staged_challenge::<C, R>(
                params,
                slot,
                challenge_alpha,
                bridge_alpha,
                inputs.take(),
            )
        })?;

        Ok(Filled { wires, derived })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::Fp;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage0::<Fp, R>::default());
        assert_stage_values(&Stage1::<Fp, R>::default());
    }
}
