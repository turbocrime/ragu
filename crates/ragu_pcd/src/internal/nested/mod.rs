//! Nested field circuits for the scalar field.
//!
//! Contains three groups of circuits:
//!
//! - **Endoscaling**: verifies that the commitment accumulation
//!   in `compute_p` was computed correctly via Horner's rule.
//! - **Loading**: enforces consistency between [`PointsStage`]
//!   inputs and the bridge stage commitments for the current step.
//! - **Copying**: enforces that [`ChildWitness`] stash fields in
//!   `BridgePreamble` match the corresponding child proof's bridge
//!   stage contents.
//!
//! [`ChildWitness`]: stages::preamble::ChildWitness
//! [`PointsStage`]: crate::internal::endoscalar::PointsStage

use alloc::vec::Vec;

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, RegistryBuilder},
    staging::MultiStage,
};
use ragu_core::Result;

pub mod circuits {
    pub mod copying;
    pub mod loading;
}

use crate::internal::{Side, endoscalar};

/// One child's contribution to the `_10_p` commitment walk: one point per
/// entry of its rx list, plus `a`, `b`, `registry_xy`, `p`, and its stashed
/// poly-query claim commitments.
///
/// Shared between [`num_endoscaling_points`] and the nested preamble's
/// `num_points` — both walk the same per-child block.
pub const fn child_endoscaling_points(child: crate::framework_hooks::HookLayout) -> usize {
    child_endoscaling_points_for(child.poly_query.polys)
}

/// [`child_endoscaling_points`] straight from a poly count, for callers holding
/// the count without the surrounding [`HookLayout`](crate::framework_hooks::HookLayout).
///
/// This is the single statement of the per-child block's decomposition: the 13
/// native rx commitments, four extras (`ab_a`, `ab_b`, `registry_xy`, `p`), and
/// one stashed claim per polynomial slot.
pub const fn child_endoscaling_points_for(polys: usize) -> usize {
    crate::internal::native::RxIndex::NUM + 4 + polys
}

/// Number of curve points accumulated during `compute_p` for nested-field
/// endoscaling verification: the `f.commitment` base point, one block per
/// child (see [`child_endoscaling_points`]), and the current step's six stage
/// components. See `_10_p` for the canonical accumulation order.
///
/// The endoscaling circuits process these points across
/// [`num_endoscaling_steps`] steps.
pub const fn num_endoscaling_points(capacity: crate::framework_hooks::HookLayout) -> usize {
    1 + 2 * child_endoscaling_points(capacity) + 6
}

/// The number of endoscaling step circuits a fuse runs: what
/// [`endoscalar::num_steps`] makes of [`num_endoscaling_points`].
pub const fn num_endoscaling_steps(capacity: crate::framework_hooks::HookLayout) -> usize {
    endoscalar::num_steps(num_endoscaling_points(capacity))
}

/// A stage's position in [`chain_layout`], so the runs and the mask
/// registration name a stage instead of an integer.
///
/// The discriminants *are* the indices — [`chain_layout`] builds its widths in
/// this order, and `nested_chain_positions_match_layout` pins that the two
/// agree. Reordering the chain means reordering both together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum ChainStage {
    Endoscalar = 0,
    Points = 1,
    Preamble = 2,
    SPrime = 3,
    InnerError = 4,
    OuterError = 5,
    Ab = 6,
    Query = 7,
    F = 8,
    Eval = 9,
}

impl ChainStage {
    /// The chain's stages in layout order — the same order
    /// [`chain_layout`] pushes widths.
    pub const ALL: [Self; 10] = [
        Self::Endoscalar,
        Self::Points,
        Self::Preamble,
        Self::SPrime,
        Self::InnerError,
        Self::OuterError,
        Self::Ab,
        Self::Query,
        Self::F,
        Self::Eval,
    ];

    /// This stage's index into [`chain_layout`].
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// The nested stage chain's value-level geometry at the application's declared
/// capacity.
///
/// The chain is linear, in [`ChainStage`] order: endoscalar → points →
/// preamble → s_prime → inner_error → outer_error → ab → query → f → eval,
/// followed by the claim and challenge bridge runs (whose layouts live with
/// their `Run` types). The points and preamble stages carry the *children's*
/// blocks, the eval stage the current step's own slots — but every step in an
/// application exposes the same shape, so one capacity sizes all three. The
/// widths come from each stage's `num_values` (capacity-dependent stages) or
/// its typed `values()` (the stages whose width really is a property of their
/// type); `nested_chain_layout_tiles_at_every_capacity` pins that the result is
/// contiguous.
pub fn chain_layout<HC: ragu_arithmetic::CurveAffine, R: Rank>(
    capacity: crate::framework_hooks::HookLayout,
) -> ragu_circuits::staging::InducedStages {
    use ragu_circuits::staging::{InducedStages, Stage};

    // The three shape-carrying stages (points, preamble, eval) take their
    // widths from the capacity; each is subdivided into one-point slots by
    // `run_layout`. The seven between them are shape-free, so their widths come
    // from their own types.
    //
    // This vector's order is `ChainStage::ALL`.
    InducedStages::new(alloc::vec![
        <endoscalar::EndoscalarStage as Stage<HC::Base, R>>::values(),
        endoscalar::points_stage_num_values(num_endoscaling_points(capacity)),
        stages::preamble::num_values(capacity),
        <stages::s_prime::Stage<HC, R> as Stage<HC::Base, R>>::values(),
        <stages::inner_error::Stage<HC, R> as Stage<HC::Base, R>>::values(),
        <stages::outer_error::Stage<HC, R> as Stage<HC::Base, R>>::values(),
        <stages::ab::Stage<HC, R> as Stage<HC::Base, R>>::values(),
        <stages::query::Stage<HC, R> as Stage<HC::Base, R>>::values(),
        <stages::f::Stage<HC, R> as Stage<HC::Base, R>>::values(),
        stages::eval::num_values(capacity),
    ])
}

/// Subdivides one span of [`chain_layout`] into `slots` one-point slots.
///
/// The three shape-carrying nested stages — points, preamble, eval — are each
/// a flat list of curve points whose length follows the application's shape.
/// Each is placed as an induced run of one-point slots inside the span
/// [`chain_layout`] already gives it, so the stage keeps its single mask and
/// single commitment: the subdivision decides where wires land, not how many
/// commitments there are.
///
/// `nested_chain_layout_tiles_at_every_capacity` pins that each run's slots sum
/// to the span they subdivide.
pub fn run_layout(
    chain: &ragu_circuits::staging::InducedStages,
    stage: ChainStage,
    slots: usize,
) -> ragu_circuits::staging::InducedStages {
    ragu_circuits::staging::InducedStages::anchored(
        chain.skip_gates(stage.index()),
        alloc::vec![2; slots],
    )
}

/// The claim-bridge run's layout: one two-wire slot per witnessed polynomial,
/// anchored right after the chain `chain` describes.
///
/// Takes the chain rather than rebuilding it — the two are always wanted
/// together, and building the chain is a ten-element allocation.
pub fn claim_run_layout(
    chain: &ragu_circuits::staging::InducedStages,
    capacity: crate::framework_hooks::HookLayout,
) -> ragu_circuits::staging::InducedStages {
    ragu_circuits::staging::InducedStages::anchored(
        chain.final_skip_gates(),
        alloc::vec![2; capacity.poly_query.polys],
    )
}

/// Every layout needed to walk a nested trace, built together.
///
/// [`loading`](circuits::loading) and [`copying`](circuits::copying) traverse
/// the same chain — the current step's and a child's respectively — and must
/// place every stage at the same gate or their wire positions diverge. A stage's
/// position depends on how wide the stages before it are, so one of them
/// disagreeing about a single width misplaces everything after it. Building both
/// walks from one value is what makes that agreement structural rather than a
/// convention two files have to keep.
pub struct NestedLayouts {
    /// The chain itself, in [`ChainStage`] order — the source of every stage's
    /// position, including the shape-free ones.
    pub chain: ragu_circuits::staging::InducedStages,
    /// [`ChainStage::Points`], subdivided into one-point slots.
    pub points: ragu_circuits::staging::InducedStages,
    /// [`ChainStage::Preamble`], subdivided into one-point slots.
    pub preamble: ragu_circuits::staging::InducedStages,
    /// [`ChainStage::Eval`], subdivided into one-point slots.
    pub eval: ragu_circuits::staging::InducedStages,
    /// The claim-bridge run, anchored where the chain ends.
    pub claims: ragu_circuits::staging::InducedStages,
    /// How many points [`points`](Self::points) places — the run's slot count,
    /// which [`Points::from_slots`](endoscalar::Points::from_slots) also needs.
    pub num_points: usize,
}

impl NestedLayouts {
    /// Builds every layout for an application of the given capacity.
    pub fn new<HC: ragu_arithmetic::CurveAffine, R: Rank>(
        capacity: crate::framework_hooks::HookLayout,
    ) -> Self {
        let chain = chain_layout::<HC, R>(capacity);
        let num_points = num_endoscaling_points(capacity);
        Self {
            points: run_layout(
                &chain,
                ChainStage::Points,
                endoscalar::points_stage_num_slots(num_points),
            ),
            preamble: run_layout(
                &chain,
                ChainStage::Preamble,
                stages::preamble::num_slots(capacity),
            ),
            eval: run_layout(&chain, ChainStage::Eval, stages::eval::num_slots(capacity)),
            claims: claim_run_layout(&chain, capacity),
            chain,
            num_points,
        }
    }

    /// The span width of a stage placed whole, for
    /// [`configure_stage_sized`](ragu_circuits::staging::StageBuilder::configure_stage_sized).
    pub fn width(&self, stage: ChainStage) -> usize {
        self.chain.width(stage.index())
    }
}

/// Positions inside the bonding block, before the per-slot masks.
const BLOCK_FIXED: [InternalCircuitIndex; 11] = [
    InternalCircuitIndex::EndoscalarStage,
    InternalCircuitIndex::PointsStage,
    InternalCircuitIndex::PointsFinalStaged,
    InternalCircuitIndex::BridgePreamble,
    InternalCircuitIndex::BridgeSPrime,
    InternalCircuitIndex::BridgeInnerError,
    InternalCircuitIndex::BridgeOuterError,
    InternalCircuitIndex::BridgeAB,
    InternalCircuitIndex::BridgeQuery,
    InternalCircuitIndex::BridgeF,
    InternalCircuitIndex::BridgeEval,
];

/// The number of nested internal circuits and bondings [`register_all`]
/// registers at `capacity`.
///
/// Layout (circuits before bondings, matching `RegistryBuilder::finalize()`):
/// the endoscaling step circuits, then one bonding block — the eleven fixed
/// entries of [`BLOCK_FIXED`], the claim bridge slot masks at the capacity's
/// poly count, the loading circuit, and the two copying circuits.
///
/// Every one of these is built at the capacity, children included, which is
/// why there is a single run and a single block rather than a family keyed by
/// shape.
pub(crate) fn num_internal(capacity: crate::framework_hooks::HookLayout) -> usize {
    num_endoscaling_steps(capacity) + BLOCK_FIXED.len() + capacity.poly_query.polys + 3
}

/// Index of internal nested circuits registered into the registry.
///
/// These correspond to the wiring objects registered in [`register_all`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternalCircuitIndex {
    /// `EndoscalingStep` circuit at given step.
    EndoscalingStep(u32),
    /// `EndoscalarStage` stage mask.
    EndoscalarStage,
    /// `PointsStage` stage mask.
    PointsStage,
    /// `PointsStage` final staged mask.
    PointsFinalStaged,
    /// Bridge `preamble` stage mask.
    BridgePreamble,
    /// Bridge `s_prime` stage mask.
    BridgeSPrime,
    /// Bridge `inner_error` stage mask.
    BridgeInnerError,
    /// Bridge `outer_error` stage mask.
    BridgeOuterError,
    /// Bridge `ab` stage mask.
    BridgeAB,
    /// Bridge `query` stage mask.
    BridgeQuery,
    /// Bridge `f` stage mask.
    BridgeF,
    /// Bridge `eval` stage mask.
    BridgeEval,
    /// Per-claim bridge stage mask, indexed by poly-query claim slot.
    BridgeClaim(u32),
    /// Loading circuit over all nested stages.
    Loading,
    /// Copying circuit relating current preamble to a child proof's stages.
    Copying(Side),
}

impl InternalCircuitIndex {
    /// All variants in canonical iteration order.
    ///
    /// This order must match the registry finalization concatenation order
    /// in [`RegistryBuilder::finalize()`](ragu_circuits::registry::RegistryBuilder::finalize)
    /// (circuits before masks), since [`circuit_index()`](Self::circuit_index)
    /// derives indices from position in this list.
    ///
    /// A runtime `Vec` rather than a `const` array: the length depends on the
    /// polynomial-slot count, which is an application parameter, and a length
    /// computed from a generic cannot size an array on stable Rust. The order
    /// is what matters here, and it is identical either way.
    pub fn all(capacity: crate::framework_hooks::HookLayout) -> Vec<Self> {
        let mut all = Vec::new();
        all.extend(
            (0..num_endoscaling_steps(capacity)).map(|step| Self::EndoscalingStep(step as u32)),
        );
        all.extend([
            Self::EndoscalarStage,
            Self::PointsStage,
            Self::PointsFinalStaged,
            Self::BridgePreamble,
            Self::BridgeSPrime,
            Self::BridgeInnerError,
            Self::BridgeOuterError,
            Self::BridgeAB,
            Self::BridgeQuery,
            Self::BridgeF,
            Self::BridgeEval,
        ]);
        all.extend((0..capacity.poly_query.polys).map(|i| Self::BridgeClaim(i as u32)));
        all.extend([
            Self::Loading,
            Self::Copying(Side::Left),
            Self::Copying(Side::Right),
        ]);
        all
    }

    /// Convert to a [`CircuitIndex`] for registry lookup.
    ///
    /// Circuit indices follow the `RegistryBuilder::finalize()` concatenation
    /// order: internal circuits first, then internal masks.
    pub fn circuit_index(self, capacity: crate::framework_hooks::HookLayout) -> CircuitIndex {
        let pos = Self::all(capacity)
            .iter()
            .position(|&v| v == self)
            .expect("every variant appears in `all`");
        CircuitIndex::new(pos)
    }
}

/// Enum identifying which nested field rx polynomial to retrieve from a proof.
///
/// Analogous to [`native::RxIndex`](super::native::RxIndex) for the scalar
/// field. Each variant maps to a polynomial in
/// the proof's nested-field polynomial storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildBridgeKind {
    /// Child proof's `BridgeSPrime` rx polynomial.
    SPrime,
    /// Child proof's `BridgeInnerError` rx polynomial.
    InnerError,
    /// Child proof's `BridgeOuterError` rx polynomial.
    OuterError,
    /// Child proof's `BridgeAB` rx polynomial.
    AB,
    /// Child proof's `BridgeQuery` rx polynomial.
    Query,
    /// Child proof's `BridgeEval` rx polynomial.
    Eval,
}

impl ChildBridgeKind {
    /// All kinds in the canonical slot order.
    ///
    /// This constant is the source of truth for the relative order of
    /// `RxIndex::ChildBridge(kind, side)` entries in [`RxIndex::all`]
    /// and is therefore pinned by
    /// `test_nested_registry_digest` — re-ordering these variants
    /// changes the nested registry digest.
    pub const ALL: [Self; 6] = [
        Self::SPrime,
        Self::InnerError,
        Self::OuterError,
        Self::AB,
        Self::Query,
        Self::Eval,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxIndex {
    /// EndoscalingStep circuit rx polynomial (indexed by step number).
    EndoscalingStep(u32),
    /// EndoscalarStage rx polynomial.
    EndoscalarStage,
    /// PointsStage rx polynomial.
    PointsStage,
    /// Bridge `preamble` rx polynomial.
    BridgePreamble,
    /// Bridge `s_prime` rx polynomial.
    BridgeSPrime,
    /// Bridge `inner_error` rx polynomial.
    BridgeInnerError,
    /// Bridge `outer_error` rx polynomial.
    BridgeOuterError,
    /// Bridge `ab` rx polynomial.
    BridgeAB,
    /// Bridge `query` rx polynomial.
    BridgeQuery,
    /// Bridge `f` rx polynomial.
    BridgeF,
    /// Bridge `eval` rx polynomial.
    BridgeEval,
    /// Per-claim bridge rx polynomial, indexed by poly-query claim slot.
    BridgeClaim(u32),
    /// Child proof's `PointsStage` rx polynomial (per-side, for copying).
    ChildPointsStage(Side),
    /// Child proof's bridge rx polynomial (per-side, for copying),
    /// keyed by which bridge stage it comes from.
    ChildBridge(ChildBridgeKind, Side),
}

impl RxIndex {
    /// All variants in canonical order (circuits, then stages), at the given
    /// capacity.
    ///
    /// Must maintain the same ordering convention as
    /// [`native::RxIndex::ALL`](super::native::RxIndex::ALL) — which stays a
    /// `const` array, since the native side's count does not depend on the
    /// polynomial-slot count. See [`InternalCircuitIndex::all`] for why this
    /// one cannot.
    pub fn all(capacity: crate::framework_hooks::HookLayout) -> Vec<Self> {
        let mut all = Vec::new();
        all.extend(
            (0..num_endoscaling_steps(capacity)).map(|step| Self::EndoscalingStep(step as u32)),
        );
        all.extend([
            Self::EndoscalarStage,
            Self::PointsStage,
            Self::BridgePreamble,
            Self::BridgeSPrime,
            Self::BridgeInnerError,
            Self::BridgeOuterError,
            Self::BridgeAB,
            Self::BridgeQuery,
            Self::BridgeF,
            Self::BridgeEval,
        ]);
        all.extend((0..capacity.poly_query.polys).map(|i| Self::BridgeClaim(i as u32)));
        all.extend([
            Self::ChildPointsStage(Side::Left),
            Self::ChildPointsStage(Side::Right),
        ]);
        for kind in ChildBridgeKind::ALL {
            all.extend([
                Self::ChildBridge(kind, Side::Left),
                Self::ChildBridge(kind, Side::Right),
            ]);
        }
        all
    }
}

pub mod claims;

pub mod stages {
    pub mod ab;
    pub mod claim_bridge;
    pub mod eval;
    pub mod f;
    pub mod host_bridge;
    pub mod inner_error;
    pub mod outer_error;
    pub mod preamble;
    pub mod query;
    pub mod s_prime;
}

/// Registers internal nested circuits into the provided registry: the
/// endoscaling step circuits, then the bonding block — in exactly the order
/// [`num_internal`] documents.
///
/// Circuits are registered as internal to ensure they occupy prefix indices
/// before application steps.
pub fn register_all<'params, C: Cycle, R: Rank>(
    mut registry: RegistryBuilder<'params, C::ScalarField, R>,
    capacity: crate::framework_hooks::HookLayout,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>> {
    let initial_internal_circuits = registry.num_internal_circuits();

    // Circuits first, then bondings - matching RegistryBuilder::finalize()'s
    // concatenation order and the layout `num_internal` documents.
    {
        let num_points = num_endoscaling_points(capacity);
        for step in 0..num_endoscaling_steps(capacity) {
            let step_circuit =
                endoscalar::EndoscalingStep::<C::HostCurve, R>::new(step, num_points);
            registry = registry.register_internal_circuit(MultiStage::new(step_circuit))?;
        }
    }

    {
        let chain = chain_layout::<C::HostCurve, R>(capacity);
        let claim_layout = claim_run_layout(&chain, capacity);

        // The fixed block, in BLOCK_FIXED order: endoscalar, points, points
        // final, then the eight bridge masks in chain order.
        registry = registry
            .register_bonding(chain.mask::<C::ScalarField, R>(ChainStage::Endoscalar.index())?);
        registry =
            registry.register_bonding(chain.mask::<C::ScalarField, R>(ChainStage::Points.index())?);
        registry = registry.register_bonding(
            chain.final_mask_through::<C::ScalarField, R>(ChainStage::Points.index())?,
        );
        for stage in &ChainStage::ALL[ChainStage::Preamble.index()..] {
            registry = registry.register_bonding(chain.mask::<C::ScalarField, R>(stage.index())?);
        }

        for slot in 0..capacity.poly_query.polys {
            registry = registry.register_bonding(claim_layout.mask::<C::ScalarField, R>(slot)?);
        }

        let circuit = circuits::loading::Circuit::<C::HostCurve, R>::new(capacity);
        registry = registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?);

        for side in [Side::Left, Side::Right] {
            // A copying circuit walks a CHILD of the proof being fused, but
            // every step in the application exposes the capacity — children
            // included — so the same value serves here.
            let circuit = circuits::copying::Circuit::<C::HostCurve, R>::new(side, capacity);
            registry = registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?);
        }
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + num_internal(capacity),
        "internal circuit count mismatch"
    );

    Ok(registry)
}
