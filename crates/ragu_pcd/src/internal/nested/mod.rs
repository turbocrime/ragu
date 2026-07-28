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

/// Number of curve points accumulated during `compute_p` for nested field
/// endoscaling verification.
///
/// This is the sum of per-child commitment components (for both proofs: one
/// per [`RxIndex`](crate::internal::native::RxIndex) — challenge stages
/// included — plus `a`, `b`, `registry_xy`, `p`, and the poly-query claim host
/// commitments), current-step stage proof components, and the `f.commitment`
/// base polynomial. See `_10_p` for the canonical accumulation order.
///
/// The endoscaling circuits process these points across
/// [`NUM_ENDOSCALING_STEPS`] steps.
/// The point count at the typed placeholder shape — for
/// [`PointsStage`](crate::internal::endoscalar::PointsStage)'s typed
/// `values()` and `Default`, which take no shape. Every real construction is
/// sized by [`num_endoscaling_points`] at the application's capacity.
pub const NUM_ENDOSCALING_POINTS: usize = num_endoscaling_points(
    crate::framework_hooks::HookLayout::typed_placeholder(),
    crate::framework_hooks::HookLayout::typed_placeholder(),
);

/// One child's contribution to the `_10_p` commitment walk: one point per
/// entry of its rx list (challenge stages at its own count), plus `a`, `b`,
/// `registry_xy`, `p`, and its stashed poly-query claim commitments.
///
/// Shared between [`num_endoscaling_points`] and the nested preamble's
/// `num_points` — both walk the same per-child block.
pub const fn child_endoscaling_points(child: crate::framework_hooks::HookLayout) -> usize {
    crate::internal::native::RxIndex::NUM + 4 + child.poly_query.polys
}

/// [`NUM_ENDOSCALING_POINTS`] for children of the given shapes: the base
/// point, each child's block at its own shape, and the current step's six
/// stage components.
pub const fn num_endoscaling_points(
    left: crate::framework_hooks::HookLayout,
    right: crate::framework_hooks::HookLayout,
) -> usize {
    1 + child_endoscaling_points(left) + child_endoscaling_points(right) + 6
}

/// [`NUM_ENDOSCALING_STEPS`] for children of the given shapes.
pub const fn num_endoscaling_steps(
    left: crate::framework_hooks::HookLayout,
    right: crate::framework_hooks::HookLayout,
) -> usize {
    endoscalar::num_steps(num_endoscaling_points(left, right))
}

/// Number of endoscaling steps, derived from [`NUM_ENDOSCALING_POINTS`] via
/// [`endoscalar::num_steps`].
#[allow(dead_code)] // documentation anchor; the value path uses num_endoscaling_steps
const NUM_ENDOSCALING_STEPS: usize = endoscalar::num_steps(NUM_ENDOSCALING_POINTS);

/// The nested stage chain's value-level geometry for a step of shape `own`
/// fusing children of shapes `left` and `right`.
///
/// The chain is linear: endoscalar → points → preamble → s_prime →
/// inner_error → outer_error → ab → query → f → eval, followed by the claim
/// and challenge bridge runs (whose layouts live with their `Run` types). The
/// points and preamble stages carry the *children's* blocks, the eval stage
/// the current step's own slots. The widths come from each stage's
/// `num_values` (count-dependent stages) or its typed `values()` (count-free
/// stages), so the layout agrees with the typed chain by construction;
/// `nested_chain_layout_tiles_typed_chain` pins it.
pub fn chain_layout<HC: ragu_arithmetic::CurveAffine, R: Rank>(
    own: crate::framework_hooks::HookLayout,
    left: crate::framework_hooks::HookLayout,
    right: crate::framework_hooks::HookLayout,
) -> ragu_circuits::staging::InducedStages {
    use ragu_circuits::staging::{InducedStages, Stage};

    InducedStages::new(alloc::vec![
        <endoscalar::EndoscalarStage as Stage<HC::Base, R>>::values(),
        endoscalar::points_stage_num_values(num_endoscaling_points(left, right)),
        stages::preamble::num_values(left, right),
        <stages::s_prime::Stage<HC, R> as Stage<HC::Base, R>>::values(),
        <stages::inner_error::Stage<HC, R> as Stage<HC::Base, R>>::values(),
        <stages::outer_error::Stage<HC, R> as Stage<HC::Base, R>>::values(),
        <stages::ab::Stage<HC, R> as Stage<HC::Base, R>>::values(),
        <stages::query::Stage<HC, R> as Stage<HC::Base, R>>::values(),
        <stages::f::Stage<HC, R> as Stage<HC::Base, R>>::values(),
        stages::eval::num_values(own),
    ])
}

/// The claim-bridge run's layout for a step of shape `own` fusing children of
/// shapes `left` and `right`: one two-wire slot per witnessed polynomial,
/// anchored right after the chain [`chain_layout`] describes.
pub fn claim_run_layout<HC: ragu_arithmetic::CurveAffine, R: Rank>(
    own: crate::framework_hooks::HookLayout,
    left: crate::framework_hooks::HookLayout,
    right: crate::framework_hooks::HookLayout,
) -> ragu_circuits::staging::InducedStages {
    ragu_circuits::staging::InducedStages::anchored(
        chain_layout::<HC, R>(own, left, right).final_skip_gates(),
        alloc::vec![2; own.poly_query.polys],
    )
}

/// The nested internal-circuit index space for a variant registry.
///
/// Layout (circuits before bondings, matching `RegistryBuilder::finalize()`):
/// the endoscaling step circuits, one run per ordered (left, right) pair
/// (their count is a function of the children's shapes only); then one
/// bonding block per (own, left, right) triple — the endoscalar, points, and
/// points-final masks, the eight fixed bridge masks, the claim and challenge
/// bridge slot masks at `own`'s counts, the loading circuit, and the two
/// copying circuits (which walk a *child* of that triple).
#[derive(Clone, Debug)]
pub(crate) struct NestedIndexSpace {
    space: crate::internal::VariantSpace,
    /// Endoscaling-step index of each pair's first step circuit, plus the
    /// total as a final entry.
    endo_offsets: Vec<usize>,
    /// Bonding index of each triple's block start (relative to the first
    /// bonding), plus the total as a final entry.
    block_offsets: Vec<usize>,
}

/// Positions inside a triple's bonding block, before the per-slot masks.
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

#[allow(dead_code)] // the flip's consumer-switch commit takes these up
impl NestedIndexSpace {
    pub(crate) fn new(space: crate::internal::VariantSpace) -> Self {
        let mut endo_offsets = Vec::with_capacity(space.num_pairs() + 1);
        let mut acc = 0;
        for (l, r) in space.pairs() {
            endo_offsets.push(acc);
            acc += num_endoscaling_steps(l, r);
        }
        endo_offsets.push(acc);

        let mut block_offsets = Vec::with_capacity(space.num_triples() + 1);
        let mut acc = 0;
        for (own, _, _) in space.triples() {
            block_offsets.push(acc);
            acc += Self::block_len(own);
        }
        block_offsets.push(acc);

        Self {
            space,
            endo_offsets,
            block_offsets,
        }
    }

    pub(crate) fn space(&self) -> &crate::internal::VariantSpace {
        &self.space
    }

    /// One triple's bonding-block length.
    fn block_len(own: crate::framework_hooks::HookLayout) -> usize {
        BLOCK_FIXED.len() + own.poly_query.polys + 3
    }

    /// Total nested internal circuits and bondings.
    pub(crate) fn num_internal(&self) -> usize {
        self.num_circuits() + self.block_offsets[self.space.num_triples()]
    }

    /// Total endoscaling step circuits (the circuits-section length).
    fn num_circuits(&self) -> usize {
        self.endo_offsets[self.space.num_pairs()]
    }

    /// Registry index of an endoscaling step circuit for children of the
    /// given shapes.
    pub(crate) fn endoscaling_step_index(
        &self,
        left: crate::framework_hooks::HookLayout,
        right: crate::framework_hooks::HookLayout,
        step: usize,
    ) -> CircuitIndex {
        let pair = self.space.pair_index(left, right);
        assert!(step < self.endo_offsets[pair + 1] - self.endo_offsets[pair]);
        CircuitIndex::new(self.endo_offsets[pair] + step)
    }

    /// Bonding index of the given triple's block start.
    fn block_start(
        &self,
        own: crate::framework_hooks::HookLayout,
        left: crate::framework_hooks::HookLayout,
        right: crate::framework_hooks::HookLayout,
    ) -> usize {
        self.num_circuits() + self.block_offsets[self.space.triple_index(own, left, right)]
    }

    /// Registry index of a fixed (non-slot) mask or circuit in a triple's
    /// block.
    ///
    /// # Panics
    ///
    /// Panics for slot-indexed or side-indexed categories (use the dedicated
    /// methods) or for shapes outside the space.
    pub(crate) fn circuit_index(
        &self,
        category: InternalCircuitIndex,
        own: crate::framework_hooks::HookLayout,
        left: crate::framework_hooks::HookLayout,
        right: crate::framework_hooks::HookLayout,
    ) -> CircuitIndex {
        let start = self.block_start(own, left, right);
        if let Some(pos) = BLOCK_FIXED.iter().position(|&c| c == category) {
            return CircuitIndex::new(start + pos);
        }
        if category == InternalCircuitIndex::Loading {
            return CircuitIndex::new(start + BLOCK_FIXED.len() + own.poly_query.polys);
        }
        unreachable!("slot- and side-indexed categories have dedicated methods");
    }

    /// Registry index of a claim-bridge slot mask in a triple's block.
    pub(crate) fn claim_slot_index(
        &self,
        own: crate::framework_hooks::HookLayout,
        left: crate::framework_hooks::HookLayout,
        right: crate::framework_hooks::HookLayout,
        slot: usize,
    ) -> CircuitIndex {
        assert!(slot < own.poly_query.polys);
        CircuitIndex::new(self.block_start(own, left, right) + BLOCK_FIXED.len() + slot)
    }

    /// Registry index of a copying circuit that walks a child of the given
    /// triple.
    pub(crate) fn copying_index(
        &self,
        side: Side,
        child: crate::framework_hooks::HookLayout,
        child_left: crate::framework_hooks::HookLayout,
        child_right: crate::framework_hooks::HookLayout,
    ) -> CircuitIndex {
        let side_offset = match side {
            Side::Left => 1,
            Side::Right => 2,
        };
        CircuitIndex::new(
            self.block_start(child, child_left, child_right)
                + BLOCK_FIXED.len()
                + child.poly_query.polys
                + side_offset,
        )
    }
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
    /// The number of internal circuits registered by [`register_all`] for a
    /// step of shape `own` fusing children of shapes `left` and `right` — the
    /// number of entries [`all`](Self::all) yields.
    pub fn num(
        own: crate::framework_hooks::HookLayout,
        left: crate::framework_hooks::HookLayout,
        right: crate::framework_hooks::HookLayout,
    ) -> usize {
        num_endoscaling_steps(left, right) + 14 + own.poly_query.polys
    }

    /// All variants in canonical iteration order. The endoscaling steps are a
    /// function of the *children's* shapes (their points are what the current
    /// step endoscales); the claim bridge slots are the current step's own.
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
    pub fn all(
        own: crate::framework_hooks::HookLayout,
        left: crate::framework_hooks::HookLayout,
        right: crate::framework_hooks::HookLayout,
    ) -> Vec<Self> {
        let mut all = Vec::with_capacity(Self::num(own, left, right));
        all.extend(
            (0..num_endoscaling_steps(left, right)).map(|step| Self::EndoscalingStep(step as u32)),
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
        all.extend((0..own.poly_query.polys).map(|i| Self::BridgeClaim(i as u32)));
        all.extend([
            Self::Loading,
            Self::Copying(Side::Left),
            Self::Copying(Side::Right),
        ]);
        debug_assert_eq!(all.len(), Self::num(own, left, right));
        all
    }

    /// Convert to a [`CircuitIndex`] for registry lookup.
    ///
    /// Circuit indices follow the `RegistryBuilder::finalize()` concatenation
    /// order: internal circuits first, then internal masks.
    pub fn circuit_index(
        self,
        own: crate::framework_hooks::HookLayout,
        left: crate::framework_hooks::HookLayout,
        right: crate::framework_hooks::HookLayout,
    ) -> CircuitIndex {
        let pos = Self::all(own, left, right)
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
    /// The number of rx components in the nested field — the number of
    /// entries [`all`](Self::all) yields. Keyed like
    /// [`InternalCircuitIndex::num`]: endoscaling steps by the children's
    /// shapes, bridge slots by the current step's own.
    pub fn num(
        own: crate::framework_hooks::HookLayout,
        left: crate::framework_hooks::HookLayout,
        right: crate::framework_hooks::HookLayout,
    ) -> usize {
        num_endoscaling_steps(left, right) + 24 + own.poly_query.polys
    }

    /// All variants in canonical order (circuits, then stages), for an
    /// application with `max_witnessed_polys` polynomial slots.
    ///
    /// Must maintain the same ordering convention as
    /// [`native::RxIndex::ALL`](super::native::RxIndex::ALL) — which stays a
    /// `const` array, since the native side's count does not depend on the
    /// polynomial-slot count. See [`InternalCircuitIndex::all`] for why this
    /// one cannot.
    pub fn all(
        own: crate::framework_hooks::HookLayout,
        left: crate::framework_hooks::HookLayout,
        right: crate::framework_hooks::HookLayout,
    ) -> Vec<Self> {
        let mut all = Vec::with_capacity(Self::num(own, left, right));
        all.extend(
            (0..num_endoscaling_steps(left, right)).map(|step| Self::EndoscalingStep(step as u32)),
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
        all.extend((0..own.poly_query.polys).map(|i| Self::BridgeClaim(i as u32)));
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
        debug_assert_eq!(all.len(), Self::num(own, left, right));
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
/// endoscaling step circuits per ordered (left, right) pair, then one bonding
/// block per (own, left, right) triple — in exactly the order
/// [`NestedIndexSpace`] resolves indices.
///
/// Circuits are registered as internal to ensure they occupy prefix indices
/// before application steps.
pub fn register_all<'params, C: Cycle, R: Rank>(
    mut registry: RegistryBuilder<'params, C::ScalarField, R>,
    index_space: &NestedIndexSpace,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>> {
    let initial_internal_circuits = registry.num_internal_circuits();
    let space = index_space.space();

    // Circuits first, then bondings - matching RegistryBuilder::finalize()'s
    // concatenation order and NestedIndexSpace's layout.
    for (left, right) in space.pairs() {
        let num_points = num_endoscaling_points(left, right);
        for step in 0..num_endoscaling_steps(left, right) {
            let step_circuit =
                endoscalar::EndoscalingStep::<C::HostCurve, R>::new(step, num_points);
            registry = registry.register_internal_circuit(MultiStage::new(step_circuit))?;
        }
    }

    for (own, left, right) in space.triples() {
        let chain = chain_layout::<C::HostCurve, R>(own, left, right);
        let claim_layout = claim_run_layout::<C::HostCurve, R>(own, left, right);

        // The fixed block, in BLOCK_FIXED order: endoscalar, points, points
        // final, then the eight bridge masks in chain order.
        registry = registry.register_bonding(chain.mask::<C::ScalarField, R>(0)?);
        registry = registry.register_bonding(chain.mask::<C::ScalarField, R>(1)?);
        registry = registry.register_bonding(chain.final_mask_through::<C::ScalarField, R>(1)?);
        for stage in 2..=9 {
            registry = registry.register_bonding(chain.mask::<C::ScalarField, R>(stage)?);
        }

        for slot in 0..own.poly_query.polys {
            registry = registry.register_bonding(claim_layout.mask::<C::ScalarField, R>(slot)?);
        }

        let circuit = circuits::loading::Circuit::<C::HostCurve, R>::new(own, left, right);
        registry = registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?);

        for side in [Side::Left, Side::Right] {
            // A copying circuit registered in triple t's block walks a CHILD
            // of triple t: the child's own shape is `own`, the grandchildren's
            // are `left` and `right`.
            let circuit =
                circuits::copying::Circuit::<C::HostCurve, R>::new(side, own, left, right);
            registry = registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?);
        }
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + index_space.num_internal(),
        "internal circuit count mismatch"
    );

    Ok(registry)
}
