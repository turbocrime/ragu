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

/// One child's block in the `_10_p` commitment walk: its native rx
/// commitments, four extras (`ab_a`, `ab_b`, `registry_xy`, `p`), one stashed
/// claim per polynomial slot, plus `C_q` when any slots exist. Shared by
/// [`num_endoscaling_points`], the nested preamble, and the native eval stage
/// so the accumulation, stash, and `v` fold orders cannot drift apart.
pub const fn child_endoscaling_points(polys: usize) -> usize {
    crate::internal::native::RxIndex::NUM + 4 + polys + q_slots(polys)
}

/// One `q` per child when the shape has any polynomial slots, none at
/// `polys == 0` so that shape's digests stay unmoved.
pub const fn q_slots(polys: usize) -> usize {
    if polys == 0 { 0 } else { 1 }
}

/// Number of curve points accumulated during `compute_p`: the `f.commitment`
/// base point, one block per child ([`child_endoscaling_points`]), and the
/// current step's stage components. See `_10_p` for the accumulation order.
pub const fn num_endoscaling_points(polys: usize) -> usize {
    const F_COMMITMENT_BASE_POINT: usize = 1;

    F_COMMITMENT_BASE_POINT
        + 2 * child_endoscaling_points(polys)
        + crate::internal::native::stages::eval::CURRENT_STEP_COMPONENTS
}

/// The number of endoscaling step circuits a fuse runs:
/// [`endoscalar::num_steps`] of [`num_endoscaling_points`].
pub const fn num_endoscaling_steps(polys: usize) -> usize {
    endoscalar::num_steps(num_endoscaling_points(polys))
}

/// [`num_endoscaling_points`] at the type level, for a poly count `L`: the
/// [`Len`](ragu_primitives::vec::Len) that [`endoscalar::Points`] and
/// [`endoscalar::EndoscalingStep`] are parameterized by.
pub struct EndoPoints<L: ragu_primitives::vec::Len>(core::marker::PhantomData<L>);

impl<L: ragu_primitives::vec::Len> ragu_primitives::vec::Len for EndoPoints<L> {
    fn len() -> usize {
        num_endoscaling_points(L::len())
    }
}

/// A stage's position in [`NestedLayouts::chain_layout`]. The discriminants
/// *are* the indices, pinned by `nested_chain_positions_match_layout`;
/// reordering the chain means reordering both together.
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
    /// [`NestedLayouts::chain_layout`] pushes widths.
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

    /// This stage's index into [`NestedLayouts::chain_layout`].
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// Subdivides one span of [`NestedLayouts::chain_layout`] into `slots`
/// one-point slots. The stage keeps its single mask and commitment: the
/// subdivision decides where wires land, and the slot width comes from `Slot`.
fn run_layout<F, R, Slot>(
    chain: &ragu_circuits::staging::InducedStages,
    stage: ChainStage,
    slots: usize,
) -> ragu_circuits::staging::InducedStages
where
    F: ragu_arithmetic::ff::Field,
    R: Rank,
    Slot: ragu_circuits::staging::Stage<F, R>,
{
    ragu_circuits::staging::InducedStages::anchored(
        chain.skip_gates(stage.index()),
        alloc::vec![Slot::values(); slots],
    )
}

/// Every layout needed to walk a nested trace, built together:
/// [`loading`](circuits::loading) and [`copying`](circuits::copying) must
/// place every stage at the same gate, so both walks come from one value.
pub struct NestedLayouts {
    /// The chain itself, in [`ChainStage`] order.
    pub chain: ragu_circuits::staging::InducedStages,
    /// [`ChainStage::Points`], subdivided into one-point slots.
    pub points: ragu_circuits::staging::InducedStages,
    /// [`ChainStage::Preamble`], subdivided into one-point slots.
    pub preamble: ragu_circuits::staging::InducedStages,
    /// [`ChainStage::Eval`], subdivided into one-point slots.
    pub eval: ragu_circuits::staging::InducedStages,
}

impl NestedLayouts {
    /// The nested stage chain's widths at the application's declared capacity,
    /// in [`ChainStage`] order — the source [`new`](Self::new) subdivides.
    /// Every step exposes the same shape, so one capacity sizes all stages.
    pub fn chain_layout<HC: ragu_arithmetic::CurveAffine, R: Rank>(
        polys: usize,
    ) -> ragu_circuits::staging::InducedStages {
        use ragu_circuits::staging::{InducedStages, Stage};

        // This vector's order is `ChainStage::ALL`.
        InducedStages::new(alloc::vec![
            <endoscalar::EndoscalarStage as Stage<HC::Base, R>>::values(),
            endoscalar::points_stage_num_values(num_endoscaling_points(polys)),
            stages::preamble::num_values(polys),
            <stages::s_prime::Stage<HC, R> as Stage<HC::Base, R>>::values(),
            <stages::inner_error::Stage<HC, R> as Stage<HC::Base, R>>::values(),
            <stages::outer_error::Stage<HC, R> as Stage<HC::Base, R>>::values(),
            <stages::ab::Stage<HC, R> as Stage<HC::Base, R>>::values(),
            <stages::query::Stage<HC, R> as Stage<HC::Base, R>>::values(),
            <stages::f::Stage<HC, R> as Stage<HC::Base, R>>::values(),
            stages::eval::num_values(polys),
        ])
    }

    /// The number of nested internal circuits and bondings [`register_all`]
    /// registers: the endoscaling steps, then [`BLOCK_FIXED`], the loading
    /// circuit, and the two copying circuits — circuits before bondings.
    pub(crate) fn num_internal(polys: usize) -> usize {
        num_endoscaling_steps(polys) + BLOCK_FIXED.len() + 3
    }

    /// Builds every layout for an application of the given capacity.
    pub fn new<HC: ragu_arithmetic::CurveAffine, R: Rank>(polys: usize) -> Self {
        let chain = Self::chain_layout::<HC, R>(polys);
        let num_points = num_endoscaling_points(polys);
        Self {
            points: run_layout::<HC::Base, R, endoscalar::PointSlotStage<HC, R>>(
                &chain,
                ChainStage::Points,
                endoscalar::points_stage_num_slots(num_points),
            ),
            preamble: run_layout::<HC::Base, R, stages::host_bridge::Slot<HC, R>>(
                &chain,
                ChainStage::Preamble,
                stages::preamble::num_slots(polys),
            ),
            eval: run_layout::<HC::Base, R, stages::host_bridge::Slot<HC, R>>(
                &chain,
                ChainStage::Eval,
                stages::eval::num_slots(polys),
            ),
            chain,
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
    pub fn all(polys: usize) -> Vec<Self> {
        let mut all = Vec::new();
        all.extend(
            (0..num_endoscaling_steps(polys)).map(|step| Self::EndoscalingStep(step as u32)),
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
    pub fn circuit_index(self, polys: usize) -> CircuitIndex {
        let pos = Self::all(polys)
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
    /// [`native::RxIndex::ALL`](super::native::RxIndex::ALL).
    pub fn all(polys: usize) -> Vec<Self> {
        let mut all = Vec::new();
        all.extend(
            (0..num_endoscaling_steps(polys)).map(|step| Self::EndoscalingStep(step as u32)),
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
    pub mod eval;
    pub mod f;
    pub mod host_bridge;
    pub mod inner_error;
    pub mod outer_error;
    pub mod preamble;
    pub mod query;
    pub mod s_prime;
}

/// Registers internal nested circuits into the provided registry, in the
/// order [`NestedLayouts::num_internal`] documents.
///
/// Circuits are registered as internal to ensure they occupy prefix indices
/// before application steps.
pub fn register_all<'params, C: Cycle, R: Rank, L: ragu_primitives::vec::Len>(
    mut registry: RegistryBuilder<'params, C::ScalarField, R>,
    polys: usize,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>> {
    let initial_internal_circuits = registry.num_internal_circuits();

    // Circuits first, then bondings - matching RegistryBuilder::finalize()'s
    // concatenation order and the layout `NestedLayouts::num_internal` documents.
    {
        for step in 0..num_endoscaling_steps(polys) {
            let step_circuit =
                endoscalar::EndoscalingStep::<C::HostCurve, R, EndoPoints<L>>::new(step);
            registry = registry.register_internal_circuit(MultiStage::new(step_circuit))?;
        }
    }

    {
        let chain = NestedLayouts::chain_layout::<C::HostCurve, R>(polys);

        // The fixed block, in BLOCK_FIXED order.
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

        let circuit = circuits::loading::Circuit::<C::HostCurve, R, L>::new();
        registry = registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?);

        for side in [Side::Left, Side::Right] {
            // A copying circuit walks a child, but children expose the same
            // capacity, so the same `L` serves here.
            let circuit = circuits::copying::Circuit::<C::HostCurve, R, L>::new(side);
            registry = registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?);
        }
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + NestedLayouts::num_internal(polys),
        "internal circuit count mismatch"
    );

    Ok(registry)
}
