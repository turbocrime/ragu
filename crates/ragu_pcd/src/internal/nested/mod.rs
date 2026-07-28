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
pub const NUM_ENDOSCALING_POINTS: usize = num_endoscaling_points(
    crate::framework_hooks::HookLayout::padded(),
    crate::framework_hooks::HookLayout::padded(),
);

/// One child's contribution to the `_10_p` commitment walk: one point per
/// entry of its rx list (challenge stages at its own count), plus `a`, `b`,
/// `registry_xy`, `p`, and its stashed poly-query claim commitments.
///
/// Shared between [`num_endoscaling_points`] and the nested preamble's
/// `num_points` — both walk the same per-child block.
pub const fn child_endoscaling_points(child: crate::framework_hooks::HookLayout) -> usize {
    crate::internal::native::RxIndex::num(child.challenge.calls) + 4 + child.poly_query.polys
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

/// [`NUM_ENDOSCALING_POINTS`] as a [`Len`](ragu_primitives::vec::Len), which is
/// how the endoscaling types
/// take their point count.
///
/// They cannot take it as a const generic: the count is a function of the
/// polynomial-slot count, and passing a computed expression as a const generic
/// argument needs `generic_const_exprs`.
/// [`Len::len`](ragu_primitives::vec::Len::len) is an ordinary function,
/// so it may compute whatever it likes — the same escape hatch
/// [`InputsLen`](endoscalar::InputsLen) and
/// [`NumStepsLen`](endoscalar::NumStepsLen) already use.
pub struct EndoPoints;

impl ragu_primitives::vec::Len for EndoPoints {
    fn len() -> usize {
        NUM_ENDOSCALING_POINTS
    }
}

/// Number of endoscaling steps, derived from [`NUM_ENDOSCALING_POINTS`] via
/// [`endoscalar::num_steps`].
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
pub fn chain_layout<C: Cycle, R: Rank>(
    own: crate::framework_hooks::HookLayout,
    left: crate::framework_hooks::HookLayout,
    right: crate::framework_hooks::HookLayout,
) -> ragu_circuits::staging::InducedStages {
    use ragu_circuits::staging::{InducedStages, Stage};

    InducedStages::new(alloc::vec![
        <endoscalar::EndoscalarStage as Stage<C::ScalarField, R>>::values(),
        endoscalar::points_stage_num_values(num_endoscaling_points(left, right)),
        stages::preamble::num_values(left, right),
        <stages::s_prime::Stage<C::HostCurve, R> as Stage<C::ScalarField, R>>::values(),
        <stages::inner_error::Stage<C::HostCurve, R> as Stage<C::ScalarField, R>>::values(),
        <stages::outer_error::Stage<C::HostCurve, R> as Stage<C::ScalarField, R>>::values(),
        <stages::ab::Stage<C::HostCurve, R> as Stage<C::ScalarField, R>>::values(),
        <stages::query::Stage<C::HostCurve, R> as Stage<C::ScalarField, R>>::values(),
        <stages::f::Stage<C::HostCurve, R> as Stage<C::ScalarField, R>>::values(),
        stages::eval::num_values(own),
    ])
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
    /// Per-challenge bridge stage mask, indexed by challenge slot.
    BridgeChallenge(u32),
    /// Loading circuit over all nested stages.
    Loading,
    /// Copying circuit relating current preamble to a child proof's stages.
    Copying(Side),
}

impl InternalCircuitIndex {
    /// The number of internal circuits registered by [`register_all`] for an
    /// application with `max_witnessed_polys` polynomial slots and
    /// `num_challenges` challenge slots — the number of entries
    /// [`all`](Self::all) yields.
    pub fn num(
        own: crate::framework_hooks::HookLayout,
        left: crate::framework_hooks::HookLayout,
        right: crate::framework_hooks::HookLayout,
    ) -> usize {
        num_endoscaling_steps(left, right) + 14 + own.poly_query.polys + own.challenge.calls
    }

    /// All variants in canonical iteration order. The endoscaling steps are a
    /// function of the *children's* shapes (their points are what the current
    /// step endoscales); the claim and challenge bridge slots are the current
    /// step's own.
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
        all.extend((0..own.challenge.calls).map(|i| Self::BridgeChallenge(i as u32)));
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
    /// Per-challenge bridge rx polynomial, indexed by challenge slot.
    BridgeChallenge(u32),
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
        num_endoscaling_steps(left, right) + 24 + own.poly_query.polys + own.challenge.calls
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
        all.extend((0..own.challenge.calls).map(|i| Self::BridgeChallenge(i as u32)));
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
    pub mod challenge_bridge;
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

/// Registers internal nested circuits into the provided registry.
///
/// Circuits are registered as internal to ensure they occupy prefix indices
/// before application steps.
pub fn register_all<'params, C: Cycle, R: Rank>(
    mut registry: RegistryBuilder<'params, C::ScalarField, R>,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>> {
    let initial_internal_circuits = registry.num_internal_circuits();

    let chain = chain_layout::<C, R>(
        crate::framework_hooks::HookLayout::padded(),
        crate::framework_hooks::HookLayout::padded(),
        crate::framework_hooks::HookLayout::padded(),
    );

    // Circuits first, then masks — matching RegistryBuilder::finalize()
    // concatenation order and InternalCircuitIndex::circuit_index().
    for id in InternalCircuitIndex::all(
        crate::framework_hooks::HookLayout::padded(),
        crate::framework_hooks::HookLayout::padded(),
        crate::framework_hooks::HookLayout::padded(),
    ) {
        use InternalCircuitIndex::*;
        registry = match id {
            EndoscalingStep(step) => {
                let step_circuit =
                    endoscalar::EndoscalingStep::<C::HostCurve, R, EndoPoints>::new(step as usize);
                let staged = MultiStage::new(step_circuit);
                registry.register_internal_circuit(staged)?
            }
            EndoscalarStage => registry.register_bonding(chain.mask::<C::ScalarField, R>(0)?),
            PointsStage => registry.register_bonding(chain.mask::<C::ScalarField, R>(1)?),
            PointsFinalStaged => {
                registry.register_bonding(chain.final_mask_through::<C::ScalarField, R>(1)?)
            }
            BridgePreamble => registry.register_bonding(chain.mask::<C::ScalarField, R>(2)?),
            BridgeSPrime => registry.register_bonding(chain.mask::<C::ScalarField, R>(3)?),
            BridgeInnerError => registry.register_bonding(chain.mask::<C::ScalarField, R>(4)?),
            BridgeOuterError => registry.register_bonding(chain.mask::<C::ScalarField, R>(5)?),
            BridgeAB => registry.register_bonding(chain.mask::<C::ScalarField, R>(6)?),
            BridgeQuery => registry.register_bonding(chain.mask::<C::ScalarField, R>(7)?),
            BridgeF => registry.register_bonding(chain.mask::<C::ScalarField, R>(8)?),
            BridgeEval => registry.register_bonding(chain.mask::<C::ScalarField, R>(9)?),
            BridgeChallenge(slot) => registry.register_bonding(
                stages::challenge_bridge::layout::<C::HostCurve, R>()
                    .mask::<C::ScalarField, R>(slot as usize)?,
            ),
            BridgeClaim(slot) => registry.register_bonding(
                stages::claim_bridge::layout::<C::HostCurve, R>()
                    .mask::<C::ScalarField, R>(slot as usize)?,
            ),
            Loading => {
                let circuit = circuits::loading::Circuit::<C::HostCurve, R>::new();
                registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?)
            }
            Copying(side) => {
                let circuit = circuits::copying::Circuit::<C::HostCurve, R>::new(side);
                registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?)
            }
        };
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits
            + InternalCircuitIndex::num(
                crate::framework_hooks::HookLayout::padded(),
                crate::framework_hooks::HookLayout::padded(),
                crate::framework_hooks::HookLayout::padded()
            ),
        "internal circuit count mismatch"
    );

    Ok(registry)
}
