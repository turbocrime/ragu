//! Native curve circuits for recursive verification.

use alloc::vec::Vec;

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, RegistryBuilder},
};
use ragu_core::Result;
use ragu_primitives::vec::ConstLen;

use crate::{internal::fold_revdot::Parameters, step};

/// Default parameters for native revdot folding
#[derive(Clone, Copy, Default)]
pub struct RevdotParameters;

impl Parameters for RevdotParameters {
    type NumGroups = ConstLen<19>;
    type GroupSize = ConstLen<7>;
}

pub mod stages {
    pub mod eval;
    pub mod inner_error;
    pub mod outer_error;
    pub mod preamble;
    pub mod query;
}

pub mod circuits {
    pub mod challenge_binding;
    pub mod compute_v;
    pub mod hashes_1;
    pub mod hashes_2;
    pub mod inner_collapse;
    pub mod outer_collapse;
}

pub mod claims;
pub mod unified;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternalCircuitIndex {
    // Native circuits
    Hashes1Circuit,
    Hashes2Circuit,
    InnerCollapseCircuit,
    OuterCollapseCircuit,
    ComputeVCircuit,
    ChallengeBindingCircuit,
    // Native stages
    PreambleStage,
    InnerErrorStage,
    OuterErrorStage,
    QueryStage,
    EvalStage,
    // Final stage masks
    PreambleFinalStaged,
    InnerErrorFinalStaged,
    OuterErrorFinalStaged,
    EvalFinalStaged,
    /// Well-formedness mask for an application circuit's challenge stage, by
    /// slot. Shared by every application circuit: the stage geometry is a
    /// framework constant, so all of them have the same one.
    ChallengeStage(u32),
    /// Well-formedness mask for an application circuit's final trace, given the
    /// challenge stages that precede it.
    ChallengeFinalStaged,
}

/// Compute the total circuit count and log2 domain size from the number of
/// application-defined steps and the number of internal circuits and masks
/// (from [`NativeIndexSpace::num_internal`]).
pub fn total_circuit_counts(
    num_application_steps: usize,
    num_internal_circuits: usize,
) -> (usize, u32) {
    let total_circuits = num_application_steps + step::NUM_INTERNAL_STEPS + num_internal_circuits;
    let log2_circuits = total_circuits.next_power_of_two().trailing_zeros();
    (total_circuits, log2_circuits)
}

/// The native fuse stage chains' value-level geometry for children of the
/// given shapes.
///
/// The typed chain diverges after the shared preamble prefix: the **query
/// chain** is preamble → query → eval, the **error chain** is preamble →
/// outer_error → inner_error. Each returned layout describes one chain, with
/// every real stage as one slot, so masks and rx positions can be computed
/// from values — the same mechanism the challenge-stage run uses. The widths
/// come from each stage's `num_values` (count-dependent stages, each child at
/// its own shape) or its typed `values()` (count-free stages), so the layouts
/// agree with the typed chain by construction;
/// `native_chain_layouts_tile_typed_chain` pins it. `num_internal_circuits`
/// sizes the query stage's fixed-registry block.
///
/// Returns `(query_chain, error_chain)`.
pub fn chain_layouts<C: Cycle, R: Rank, const HEADER_SIZE: usize>(
    num_internal_circuits: usize,
    left: crate::framework_hooks::HookLayout,
    right: crate::framework_hooks::HookLayout,
) -> (
    ragu_circuits::staging::InducedStages,
    ragu_circuits::staging::InducedStages,
) {
    use ragu_circuits::staging::InducedStages;

    let preamble_w = stages::preamble::num_values(HEADER_SIZE, left, right);
    let query_w = stages::query::num_values(num_internal_circuits, left, right);
    let eval_w = stages::eval::num_values(left, right);
    let outer_w = <stages::outer_error::Stage<C, R, HEADER_SIZE, RevdotParameters> as
        ragu_circuits::staging::Stage<C::CircuitField, R>>::values();
    let inner_w = <stages::inner_error::Stage<C, R, HEADER_SIZE, RevdotParameters> as
        ragu_circuits::staging::Stage<C::CircuitField, R>>::values();

    (
        InducedStages::new(alloc::vec![preamble_w, query_w, eval_w]),
        InducedStages::new(alloc::vec![preamble_w, outer_w, inner_w]),
    )
}

/// The native internal-circuit index space for a variant registry: the
/// [`VariantSpace`](crate::internal::VariantSpace)'s canonical enumeration
/// laid out in registry order.
///
/// Layout (matching `RegistryBuilder::finalize()`'s circuits-before-bondings
/// concatenation): per (own, left, right) shape triple, the six internal
/// circuits in [`InternalCircuitIndex::ALL`] order; then per triple, the nine
/// stage and final-trace masks; then the shared per-slot challenge masks up
/// to the largest challenge count; then one challenge final-trace mask per
/// distinct challenge count. The `own` component enters because compute_v's
/// registry block covers the current step's own challenge masks and the
/// query stage's fixed-registry width is `16 + own.challenge.calls`.
#[derive(Clone, Debug)]
pub(crate) struct NativeIndexSpace {
    space: crate::internal::VariantSpace,
}

/// The six triple-keyed circuit categories, in [`InternalCircuitIndex::ALL`]
/// order.
const TRIPLE_CIRCUITS: [InternalCircuitIndex; 6] = [
    InternalCircuitIndex::Hashes1Circuit,
    InternalCircuitIndex::Hashes2Circuit,
    InternalCircuitIndex::InnerCollapseCircuit,
    InternalCircuitIndex::OuterCollapseCircuit,
    InternalCircuitIndex::ComputeVCircuit,
    InternalCircuitIndex::ChallengeBindingCircuit,
];

/// The nine triple-keyed mask categories, in [`InternalCircuitIndex::ALL`]
/// order.
const TRIPLE_MASKS: [InternalCircuitIndex; 9] = [
    InternalCircuitIndex::PreambleStage,
    InternalCircuitIndex::InnerErrorStage,
    InternalCircuitIndex::OuterErrorStage,
    InternalCircuitIndex::QueryStage,
    InternalCircuitIndex::EvalStage,
    InternalCircuitIndex::PreambleFinalStaged,
    InternalCircuitIndex::InnerErrorFinalStaged,
    InternalCircuitIndex::OuterErrorFinalStaged,
    InternalCircuitIndex::EvalFinalStaged,
];

#[allow(dead_code)] // the flip's consumer-switch commit takes these up
impl NativeIndexSpace {
    pub(crate) fn new(space: crate::internal::VariantSpace) -> Self {
        Self { space }
    }

    pub(crate) fn space(&self) -> &crate::internal::VariantSpace {
        &self.space
    }

    /// The total number of native internal circuits and masks.
    pub(crate) fn num_internal(&self) -> usize {
        self.space.num_triples() * (TRIPLE_CIRCUITS.len() + TRIPLE_MASKS.len())
            + self.space.max_challenges()
            + self.space.distinct_challenges().len()
    }

    /// Registry index of a triple-keyed circuit or mask category's variant.
    ///
    /// # Panics
    ///
    /// Panics for the challenge-mask categories (use
    /// [`challenge_stage_index`](Self::challenge_stage_index) /
    /// [`challenge_final_index`](Self::challenge_final_index)) or for shapes
    /// outside the space.
    pub(crate) fn circuit_index(
        &self,
        category: InternalCircuitIndex,
        own: crate::framework_hooks::HookLayout,
        left: crate::framework_hooks::HookLayout,
        right: crate::framework_hooks::HookLayout,
    ) -> CircuitIndex {
        let triple = self.space.triple_index(own, left, right);
        if let Some(pos) = TRIPLE_CIRCUITS.iter().position(|&c| c == category) {
            return CircuitIndex::new(triple * TRIPLE_CIRCUITS.len() + pos);
        }
        let circuits_end = self.space.num_triples() * TRIPLE_CIRCUITS.len();
        if let Some(pos) = TRIPLE_MASKS.iter().position(|&c| c == category) {
            return CircuitIndex::new(circuits_end + triple * TRIPLE_MASKS.len() + pos);
        }
        unreachable!("challenge-mask categories are not triple-keyed");
    }

    /// Registry index of the shared challenge-stage mask for `slot`.
    pub(crate) fn challenge_stage_index(&self, slot: usize) -> CircuitIndex {
        assert!(slot < self.space.max_challenges());
        CircuitIndex::new(
            self.space.num_triples() * (TRIPLE_CIRCUITS.len() + TRIPLE_MASKS.len()) + slot,
        )
    }

    /// Registry index of the final-trace mask for a step with `own_challenges`
    /// challenge stages.
    pub(crate) fn challenge_final_index(&self, own_challenges: usize) -> CircuitIndex {
        let pos = self
            .space
            .distinct_challenges()
            .iter()
            .position(|&c| c == own_challenges)
            .expect("challenge count was registered");
        CircuitIndex::new(
            self.space.num_triples() * (TRIPLE_CIRCUITS.len() + TRIPLE_MASKS.len())
                + self.space.max_challenges()
                + pos,
        )
    }
}

impl InternalCircuitIndex {
    /// The number of internal circuits registered by [`register_all`] for a
    /// given challenge-slot count; the value-level source of [`NUM`](Self::NUM).
    pub const fn num(num_challenges: usize) -> usize {
        16 + num_challenges
    }

    /// The number of internal circuits registered by [`register_all`],
    /// equal to the number of variants in [`InternalCircuitIndex`].
    pub const NUM: usize = Self::num(crate::NUM_CHALLENGE_SLOTS);

    /// All variants for a given challenge-slot count, in canonical iteration
    /// order; the value-level source of [`ALL`](Self::ALL). The order must
    /// match the registry finalization concatenation order, exactly as
    /// documented on [`ALL`](Self::ALL).
    #[allow(dead_code)] // superseded by NativeIndexSpace; dies with the flip
    pub fn all(num_challenges: usize) -> Vec<Self> {
        use InternalCircuitIndex::*;
        let mut all = alloc::vec![
            Hashes1Circuit,
            Hashes2Circuit,
            InnerCollapseCircuit,
            OuterCollapseCircuit,
            ComputeVCircuit,
            ChallengeBindingCircuit,
            PreambleStage,
            InnerErrorStage,
            OuterErrorStage,
            QueryStage,
            EvalStage,
            PreambleFinalStaged,
            InnerErrorFinalStaged,
            OuterErrorFinalStaged,
            EvalFinalStaged,
        ];
        all.extend((0..num_challenges).map(|i| ChallengeStage(i as u32)));
        all.push(ChallengeFinalStaged);
        assert_eq!(all.len(), Self::num(num_challenges));
        all
    }

    /// All variants in canonical iteration order.
    ///
    /// This order must match the registry finalization concatenation order
    /// in [`RegistryBuilder::finalize()`](ragu_circuits::registry::RegistryBuilder::finalize)
    /// (circuits before masks), since [`circuit_index()`](Self::circuit_index)
    /// derives indices from position in this array.
    pub const ALL: [Self; Self::NUM] = super::const_fns::unwrap_all(Self::all_slots());

    const fn all_slots() -> [Option<Self>; Self::NUM] {
        use super::const_fns::push;

        let mut slots = [None; Self::NUM];
        let mut c = 0;
        push(&mut slots, &mut c, Self::Hashes1Circuit);
        push(&mut slots, &mut c, Self::Hashes2Circuit);
        push(&mut slots, &mut c, Self::InnerCollapseCircuit);
        push(&mut slots, &mut c, Self::OuterCollapseCircuit);
        push(&mut slots, &mut c, Self::ComputeVCircuit);
        push(&mut slots, &mut c, Self::ChallengeBindingCircuit);
        push(&mut slots, &mut c, Self::PreambleStage);
        push(&mut slots, &mut c, Self::InnerErrorStage);
        push(&mut slots, &mut c, Self::OuterErrorStage);
        push(&mut slots, &mut c, Self::QueryStage);
        push(&mut slots, &mut c, Self::EvalStage);
        push(&mut slots, &mut c, Self::PreambleFinalStaged);
        push(&mut slots, &mut c, Self::InnerErrorFinalStaged);
        push(&mut slots, &mut c, Self::OuterErrorFinalStaged);
        push(&mut slots, &mut c, Self::EvalFinalStaged);
        let mut i = 0;
        while i < crate::NUM_CHALLENGE_SLOTS {
            push(&mut slots, &mut c, Self::ChallengeStage(i as u32));
            i += 1;
        }
        push(&mut slots, &mut c, Self::ChallengeFinalStaged);
        assert!(c == Self::NUM);
        slots
    }

    pub fn circuit_index(self) -> CircuitIndex {
        let pos = Self::ALL
            .iter()
            .position(|&v| v == self)
            .expect("every variant appears in ALL");
        CircuitIndex::from_u32(pos as u32)
    }
}

/// Per-internal-circuit storage indexed by [`InternalCircuitIndex`].
///
/// Each field corresponds 1:1 to a variant of [`InternalCircuitIndex`].
/// Use [`get`](Self::get) to look up by variant, and
/// [`from_fn`](Self::from_fn) / [`try_from_fn`](Self::try_from_fn) to
/// construct from a closure.
#[derive(Clone)]
pub struct InternalCircuitValues<T> {
    pub hashes_1_circuit: T,
    pub hashes_2_circuit: T,
    pub inner_collapse_circuit: T,
    pub outer_collapse_circuit: T,
    pub compute_v_circuit: T,
    pub challenge_binding_circuit: T,
    pub preamble_stage: T,
    pub inner_error_stage: T,
    pub outer_error_stage: T,
    pub query_stage: T,
    pub eval_stage: T,
    pub preamble_final_staged: T,
    pub inner_error_final_staged: T,
    pub outer_error_final_staged: T,
    pub eval_final_staged: T,
    /// One per challenge slot, in slot order. Length is the challenge-slot
    /// count the construction closure was driven with.
    pub challenge_stages: Vec<T>,
    pub challenge_final_staged: T,
}

impl<T> InternalCircuitValues<T> {
    /// Look up the value for the given internal circuit index.
    pub fn get(&self, id: InternalCircuitIndex) -> &T {
        use InternalCircuitIndex::*;
        match id {
            Hashes1Circuit => &self.hashes_1_circuit,
            Hashes2Circuit => &self.hashes_2_circuit,
            InnerCollapseCircuit => &self.inner_collapse_circuit,
            OuterCollapseCircuit => &self.outer_collapse_circuit,
            ComputeVCircuit => &self.compute_v_circuit,
            ChallengeBindingCircuit => &self.challenge_binding_circuit,
            PreambleStage => &self.preamble_stage,
            InnerErrorStage => &self.inner_error_stage,
            OuterErrorStage => &self.outer_error_stage,
            QueryStage => &self.query_stage,
            EvalStage => &self.eval_stage,
            PreambleFinalStaged => &self.preamble_final_staged,
            InnerErrorFinalStaged => &self.inner_error_final_staged,
            OuterErrorFinalStaged => &self.outer_error_final_staged,
            EvalFinalStaged => &self.eval_final_staged,
            ChallengeStage(slot) => &self.challenge_stages[slot as usize],
            ChallengeFinalStaged => &self.challenge_final_staged,
        }
    }

    /// Construct from a closure called once per variant, in
    /// [`all`](InternalCircuitIndex::all) order at the given challenge-slot
    /// count.
    pub fn from_fn(num_challenges: usize, mut f: impl FnMut(InternalCircuitIndex) -> T) -> Self {
        match Self::try_from_fn(num_challenges, |id| {
            Ok::<_, core::convert::Infallible>(f(id))
        }) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// Fallible construction from a closure called once per variant.
    ///
    /// The closure is called in [`ALL`](InternalCircuitIndex::ALL) order.
    pub fn try_from_fn<E>(
        num_challenges: usize,
        mut f: impl FnMut(InternalCircuitIndex) -> core::result::Result<T, E>,
    ) -> core::result::Result<Self, E> {
        use InternalCircuitIndex::*;
        Ok(InternalCircuitValues {
            hashes_1_circuit: f(Hashes1Circuit)?,
            hashes_2_circuit: f(Hashes2Circuit)?,
            inner_collapse_circuit: f(InnerCollapseCircuit)?,
            outer_collapse_circuit: f(OuterCollapseCircuit)?,
            compute_v_circuit: f(ComputeVCircuit)?,
            challenge_binding_circuit: f(ChallengeBindingCircuit)?,
            preamble_stage: f(PreambleStage)?,
            inner_error_stage: f(InnerErrorStage)?,
            outer_error_stage: f(OuterErrorStage)?,
            query_stage: f(QueryStage)?,
            eval_stage: f(EvalStage)?,
            preamble_final_staged: f(PreambleFinalStaged)?,
            inner_error_final_staged: f(InnerErrorFinalStaged)?,
            outer_error_final_staged: f(OuterErrorFinalStaged)?,
            eval_final_staged: f(EvalFinalStaged)?,
            challenge_stages: (0..num_challenges)
                .map(|slot| f(ChallengeStage(slot as u32)))
                .collect::<core::result::Result<_, E>>()?,
            challenge_final_staged: f(ChallengeFinalStaged)?,
        })
    }
}

/// Enum identifying which rx polynomial component to index within [`RxValues`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxIndex {
    // Circuits
    Application,
    Hashes1,
    Hashes2,
    InnerCollapse,
    OuterCollapse,
    ComputeV,
    ChallengeBinding,
    // Stages
    Preamble,
    InnerError,
    OuterError,
    Query,
    Eval,
    /// An application circuit's challenge-stage polynomial, by slot.
    ///
    /// An application circuit is multi-stage — $r(X) = r'(X) + a(X) + b(X)$ —
    /// and each challenge slot contributes one staged partial trace. Those
    /// stages are rx polynomials of the child like any other: committed per
    /// child, folded in `_10_p`, tied to the endoscaling point list in
    /// `loading`, and opened at $xz$ by `compute_v` against the quotient
    /// `_08_f` folds. Being an [`RxIndex`] variant is what gets them all of
    /// that from the same code every other component uses.
    ChallengeStage(u32),
}

impl RxIndex {
    /// The number of rx polynomial components for a given challenge-slot
    /// count; the value-level source of [`NUM`](Self::NUM).
    pub const fn num(num_challenges: usize) -> usize {
        12 + num_challenges
    }

    /// The number of rx polynomial components.
    pub const NUM: usize = Self::num(crate::NUM_CHALLENGE_SLOTS);

    /// All variants for a given challenge-slot count, in canonical order; the
    /// value-level source of [`ALL`](Self::ALL), with the same order
    /// obligations.
    pub fn all(num_challenges: usize) -> Vec<Self> {
        use RxIndex::*;
        let mut all = alloc::vec![
            Application,
            Hashes1,
            Hashes2,
            InnerCollapse,
            OuterCollapse,
            ComputeV,
            ChallengeBinding,
            Preamble,
            InnerError,
            OuterError,
            Query,
            Eval,
        ];
        all.extend((0..num_challenges).map(|i| ChallengeStage(i as u32)));
        assert_eq!(all.len(), Self::num(num_challenges));
        all
    }

    /// All variants in canonical order.
    ///
    /// This order matches the evaluation order in `poly_queries` (compute_v.rs)
    /// and `_08_f.rs`, and drives the `Write` impl for `RxValues`.
    pub const ALL: [Self; Self::NUM] = super::const_fns::unwrap_all(Self::all_slots());

    const fn all_slots() -> [Option<Self>; Self::NUM] {
        use super::const_fns::push;

        let mut slots = [None; Self::NUM];
        let mut c = 0;
        push(&mut slots, &mut c, Self::Application);
        push(&mut slots, &mut c, Self::Hashes1);
        push(&mut slots, &mut c, Self::Hashes2);
        push(&mut slots, &mut c, Self::InnerCollapse);
        push(&mut slots, &mut c, Self::OuterCollapse);
        push(&mut slots, &mut c, Self::ComputeV);
        push(&mut slots, &mut c, Self::ChallengeBinding);
        push(&mut slots, &mut c, Self::Preamble);
        push(&mut slots, &mut c, Self::InnerError);
        push(&mut slots, &mut c, Self::OuterError);
        push(&mut slots, &mut c, Self::Query);
        push(&mut slots, &mut c, Self::Eval);
        let mut i = 0;
        while i < crate::NUM_CHALLENGE_SLOTS {
            push(&mut slots, &mut c, Self::ChallengeStage(i as u32));
            i += 1;
        }
        assert!(c == Self::NUM);
        slots
    }
}

/// Per-rx-component storage indexed by [`RxIndex`].
///
/// Each field corresponds 1:1 to a variant of [`RxIndex`].
/// Use [`get`](Self::get) to look up by variant, and
/// [`try_from_fn`](Self::try_from_fn) to construct from a closure.
#[derive(Clone)]
pub struct RxValues<T> {
    pub application: T,
    pub hashes_1: T,
    pub hashes_2: T,
    pub inner_collapse: T,
    pub outer_collapse: T,
    pub compute_v: T,
    pub challenge_binding: T,
    pub preamble: T,
    pub inner_error: T,
    pub outer_error: T,
    pub query: T,
    pub eval: T,
    /// One per challenge slot, in slot order. Length is the challenge-slot
    /// count the construction closure was driven with.
    pub challenge_stages: Vec<T>,
}

impl<T> RxValues<T> {
    /// Look up the value for the given rx index.
    pub fn get(&self, id: RxIndex) -> &T {
        use RxIndex::*;
        match id {
            Application => &self.application,
            Hashes1 => &self.hashes_1,
            Hashes2 => &self.hashes_2,
            InnerCollapse => &self.inner_collapse,
            OuterCollapse => &self.outer_collapse,
            ComputeV => &self.compute_v,
            ChallengeBinding => &self.challenge_binding,
            Preamble => &self.preamble,
            InnerError => &self.inner_error,
            OuterError => &self.outer_error,
            Query => &self.query,
            Eval => &self.eval,
            ChallengeStage(slot) => &self.challenge_stages[slot as usize],
        }
    }

    /// Construct from a closure called once per variant, in
    /// [`all`](RxIndex::all) order at the given challenge-slot count.
    pub fn from_fn(num_challenges: usize, mut f: impl FnMut(RxIndex) -> T) -> Self {
        match Self::try_from_fn(num_challenges, |id| {
            Ok::<_, core::convert::Infallible>(f(id))
        }) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// Fallible construction from a closure called once per variant.
    ///
    /// The closure is called in [`ALL`](RxIndex::ALL) order.
    pub fn try_from_fn<E>(
        num_challenges: usize,
        mut f: impl FnMut(RxIndex) -> core::result::Result<T, E>,
    ) -> core::result::Result<Self, E> {
        use RxIndex::*;
        Ok(RxValues {
            application: f(Application)?,
            hashes_1: f(Hashes1)?,
            hashes_2: f(Hashes2)?,
            inner_collapse: f(InnerCollapse)?,
            outer_collapse: f(OuterCollapse)?,
            compute_v: f(ComputeV)?,
            challenge_binding: f(ChallengeBinding)?,
            preamble: f(Preamble)?,
            inner_error: f(InnerError)?,
            outer_error: f(OuterError)?,
            query: f(Query)?,
            eval: f(Eval)?,
            challenge_stages: (0..num_challenges)
                .map(|slot| f(ChallengeStage(slot as u32)))
                .collect::<core::result::Result<_, E>>()?,
        })
    }
}

/// Identifies a native-field polynomial within a proof — either one of the
/// two AB polynomials (which are not rx polynomials) or one of the 11 rx
/// polynomials addressed by [`RxIndex`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxComponent {
    /// The `a` polynomial from the AB proof (revdot claim).
    AbA,
    /// The `b` polynomial from the AB proof (revdot claim).
    AbB,
    /// An rx polynomial component indexed by [`RxIndex`].
    Rx(RxIndex),
}

/// Registers internal native circuits and masks into the provided registry:
/// one variant of every triple-keyed circuit and mask per (own, left, right)
/// shape triple in the index space, then the shared challenge-slot masks and
/// the per-count final-trace masks — in exactly the order
/// [`NativeIndexSpace`] resolves indices.
///
/// Does not register internal steps (rerandomize, trivial); those are
/// registered by the caller after this function returns.
pub fn register_all<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>(
    mut registry: RegistryBuilder<'params, C::CircuitField, R>,
    params: &'params C::Params,
    log2_circuits: u32,
    index_space: &NativeIndexSpace,
) -> Result<RegistryBuilder<'params, C::CircuitField, R>> {
    let initial_internal_circuits = registry.num_internal_circuits();
    let space = index_space.space();

    // Circuits first, then masks - matching RegistryBuilder::finalize()'s
    // concatenation order and NativeIndexSpace's layout.
    for (own, left, right) in space.triples() {
        registry = registry.register_internal_circuit(circuits::hashes_1::Circuit::<
            C,
            R,
            HEADER_SIZE,
            RevdotParameters,
        >::new(
            params, log2_circuits, left, right
        ))?;
        registry = registry.register_internal_circuit(circuits::hashes_2::Circuit::<
            C,
            R,
            HEADER_SIZE,
            RevdotParameters,
        >::new(params, left, right))?;
        registry = registry.register_internal_circuit(circuits::inner_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            RevdotParameters,
        >::new(left, right))?;
        registry = registry.register_internal_circuit(circuits::outer_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            RevdotParameters,
        >::new(left, right))?;
        registry = registry.register_internal_circuit(circuits::compute_v::Circuit::<
            C,
            R,
            HEADER_SIZE,
        >::new(
            own.challenge.calls, left, right
        ))?;
        registry = registry.register_internal_circuit(circuits::challenge_binding::Circuit::<
            C,
            R,
            HEADER_SIZE,
        >::new(params, left, right))?;
    }

    for (own, left, right) in space.triples() {
        let (query_chain, error_chain) = chain_layouts::<C, R, HEADER_SIZE>(
            InternalCircuitIndex::num(own.challenge.calls),
            left,
            right,
        );
        // Stage masks, then final-trace masks, in TRIPLE_MASKS order.
        registry = registry.register_bonding(query_chain.mask::<C::CircuitField, R>(0)?);
        registry = registry.register_bonding(error_chain.mask::<C::CircuitField, R>(2)?);
        registry = registry.register_bonding(error_chain.mask::<C::CircuitField, R>(1)?);
        registry = registry.register_bonding(query_chain.mask::<C::CircuitField, R>(1)?);
        registry = registry.register_bonding(query_chain.mask::<C::CircuitField, R>(2)?);
        registry =
            registry.register_bonding(query_chain.final_mask_through::<C::CircuitField, R>(0)?);
        registry =
            registry.register_bonding(error_chain.final_mask_through::<C::CircuitField, R>(2)?);
        registry =
            registry.register_bonding(error_chain.final_mask_through::<C::CircuitField, R>(1)?);
        registry =
            registry.register_bonding(query_chain.final_mask_through::<C::CircuitField, R>(2)?);
    }

    let max_challenges = space.max_challenges();
    for slot in 0..max_challenges {
        registry = registry.register_bonding(
            crate::step::internal::challenge_stage::layout_for(max_challenges)
                .mask::<C::CircuitField, R>(slot)?,
        );
    }
    for own_challenges in space.distinct_challenges() {
        registry = registry.register_bonding(
            crate::step::internal::challenge_stage::layout_for(own_challenges)
                .final_mask::<C::CircuitField, R>()?,
        );
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + index_space.num_internal(),
        "internal circuit count mismatch"
    );

    Ok(registry)
}
