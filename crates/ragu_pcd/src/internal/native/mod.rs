//! Native curve circuits for recursive verification.

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
}

/// Compute the total circuit count and log2 domain size from the number of
/// application-defined steps and the number of internal circuits and masks
/// (i.e. [`InternalCircuitIndex::NUM`]).
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
/// from values — the same mechanism the nested bridge runs use. The widths
/// come from each stage's `num_values` (count-dependent stages, each child at
/// its own shape) or its typed `values()` (count-free stages), so the layouts
/// agree with the typed chain by construction;
/// `native_chain_layouts_tile_typed_chain` pins it. `num_internal_circuits`
/// sizes the query stage's fixed-registry block.
///
/// Returns `(query_chain, error_chain)`.
pub fn chain_layouts<
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
>(
    num_internal_circuits: usize,
    left: crate::framework_hooks::HookLayout,
    right: crate::framework_hooks::HookLayout,
) -> (
    ragu_circuits::staging::InducedStages,
    ragu_circuits::staging::InducedStages,
) {
    use ragu_circuits::staging::InducedStages;

    let preamble_w = stages::preamble::num_values(HEADER_SIZE, left, right);
    let query_w = stages::query::num_values(num_internal_circuits);
    let eval_w = stages::eval::num_values(left, right);
    let outer_w = <stages::outer_error::Stage<C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH, RevdotParameters> as
        ragu_circuits::staging::Stage<C::CircuitField, R>>::values();
    let inner_w = <stages::inner_error::Stage<C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH, RevdotParameters> as
        ragu_circuits::staging::Stage<C::CircuitField, R>>::values();

    (
        InducedStages::new(alloc::vec![preamble_w, query_w, eval_w]),
        InducedStages::new(alloc::vec![preamble_w, outer_w, inner_w]),
    )
}

impl InternalCircuitIndex {
    /// The number of internal circuits registered by [`register_all`],
    /// equal to the number of variants in [`InternalCircuitIndex`].
    pub const NUM: usize = 15;

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
        }
    }

    /// Construct from a closure called once per variant, in
    /// [`ALL`](InternalCircuitIndex::ALL) order.
    pub fn from_fn(mut f: impl FnMut(InternalCircuitIndex) -> T) -> Self {
        match Self::try_from_fn(|id| Ok::<_, core::convert::Infallible>(f(id))) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// Fallible construction from a closure called once per variant.
    ///
    /// The closure is called in [`ALL`](InternalCircuitIndex::ALL) order.
    pub fn try_from_fn<E>(
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
}

impl RxIndex {
    /// The number of rx polynomial components.
    pub const NUM: usize = 12;

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
        }
    }

    /// Construct from a closure called once per variant, in
    /// [`ALL`](RxIndex::ALL) order.
    pub fn from_fn(mut f: impl FnMut(RxIndex) -> T) -> Self {
        match Self::try_from_fn(|id| Ok::<_, core::convert::Infallible>(f(id))) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// Fallible construction from a closure called once per variant.
    ///
    /// The closure is called in [`ALL`](RxIndex::ALL) order.
    pub fn try_from_fn<E>(
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

/// Registers internal native circuits and masks into the provided registry,
/// in exactly [`InternalCircuitIndex::ALL`] order.
///
/// Every circuit here is built for the application's settled `capacity`: the
/// slot shape every one of its steps exposes, children included. That is why
/// there is one of each rather than a family keyed by child shape.
///
/// Does not register internal steps (rerandomize, trivial); those are
/// registered by the caller after this function returns.
pub fn register_all<
    'params,
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
>(
    mut registry: RegistryBuilder<'params, C::CircuitField, R>,
    params: &'params C::Params,
    log2_circuits: u32,
    capacity: crate::framework_hooks::HookLayout,
) -> Result<RegistryBuilder<'params, C::CircuitField, R>> {
    let initial_internal_circuits = registry.num_internal_circuits();
    let (left, right) = (capacity, capacity);

    // Circuits first, then masks - matching RegistryBuilder::finalize()'s
    // concatenation order and `InternalCircuitIndex::ALL`.
    {
        registry = registry.register_internal_circuit(circuits::hashes_1::Circuit::<
            C,
            R,
            HEADER_SIZE,
            POLYS,
            CLAIMS,
            CHALLENGES,
            CHALLENGE_WIDTH,
            RevdotParameters,
        >::new(params, log2_circuits))?;
        registry = registry.register_internal_circuit(circuits::hashes_2::Circuit::<
            C,
            R,
            HEADER_SIZE,
            POLYS,
            CLAIMS,
            CHALLENGES,
            CHALLENGE_WIDTH,
            RevdotParameters,
        >::new(params))?;
        registry = registry.register_internal_circuit(circuits::inner_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            POLYS,
            CLAIMS,
            CHALLENGES,
            CHALLENGE_WIDTH,
            RevdotParameters,
        >::new())?;
        registry = registry.register_internal_circuit(circuits::outer_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            POLYS,
            CLAIMS,
            CHALLENGES,
            CHALLENGE_WIDTH,
            RevdotParameters,
        >::new())?;
        registry =
            registry.register_internal_circuit(
                circuits::compute_v::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                    POLYS,
                    CLAIMS,
                    CHALLENGES,
                    CHALLENGE_WIDTH,
                >::new(),
            )?;
        registry = registry.register_internal_circuit(circuits::challenge_binding::Circuit::<
            C,
            R,
            HEADER_SIZE,
            POLYS,
            CLAIMS,
            CHALLENGES,
            CHALLENGE_WIDTH,
        >::new(params))?;
    }

    {
        let (query_chain, error_chain) =
            chain_layouts::<C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>(
                InternalCircuitIndex::NUM,
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

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + InternalCircuitIndex::NUM,
        "internal circuit count mismatch"
    );

    Ok(registry)
}
