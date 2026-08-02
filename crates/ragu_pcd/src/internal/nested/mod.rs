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
    // The leading point is `f.commitment`'s base point.
    1 + 2 * child_endoscaling_points(polys)
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

/// The number of nested internal circuits and bondings [`register_all`]
/// registers — the cardinality of [`InternalCircuitIndex::all`].
pub(crate) fn num_internal<L: ragu_primitives::vec::Len>() -> usize {
    InternalCircuitIndex::all(L::len()).len()
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
    pub mod inner_error;
    pub mod outer_error;
    pub mod preamble;
    pub mod query;
    pub mod s_prime;
}

/// Registers internal nested circuits into the provided registry, in
/// [`InternalCircuitIndex::all`] order.
///
/// Circuits are registered as internal to ensure they occupy prefix indices
/// before application steps.
pub fn register_all<'params, C: Cycle, R: Rank, L: ragu_primitives::vec::Len>(
    mut registry: RegistryBuilder<'params, C::ScalarField, R>,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>> {
    use ragu_circuits::staging::StageExt;
    use ragu_primitives::vec::Len as _;

    use crate::internal::endoscalar::{EndoscalarStage, NumStepsLen, PointsStage};

    type ScalarOf<C> = <C as Cycle>::ScalarField;

    let initial_internal_circuits = registry.num_internal_circuits();

    // Circuits first, then bondings.
    {
        for step in 0..NumStepsLen::<EndoPoints<L>>::len() {
            let step_circuit =
                endoscalar::EndoscalingStep::<C::HostCurve, R, EndoPoints<L>>::new(step);
            registry = registry.register_internal_circuit(MultiStage::new(step_circuit))?;
        }
    }

    {
        // The fixed block, in `InternalCircuitIndex` order.
        registry = registry
            .register_bonding(<EndoscalarStage as StageExt<ScalarOf<C>, R>>::mask()?)
            .register_bonding(<PointsStage<C::HostCurve, EndoPoints<L>> as StageExt<
                ScalarOf<C>,
                R,
            >>::mask()?)
            .register_bonding(<PointsStage<C::HostCurve, EndoPoints<L>> as StageExt<
                ScalarOf<C>,
                R,
            >>::final_mask()?)
            .register_bonding(<stages::preamble::Stage<C::HostCurve, R, L> as StageExt<
                ScalarOf<C>,
                R,
            >>::mask()?)
            .register_bonding(<stages::s_prime::Stage<C::HostCurve, R, L> as StageExt<
                ScalarOf<C>,
                R,
            >>::mask()?)
            .register_bonding(
                <stages::inner_error::Stage<C::HostCurve, R, L> as StageExt<ScalarOf<C>, R>>::mask(
                )?,
            )
            .register_bonding(
                <stages::outer_error::Stage<C::HostCurve, R, L> as StageExt<ScalarOf<C>, R>>::mask(
                )?,
            )
            .register_bonding(<stages::ab::Stage<C::HostCurve, R, L> as StageExt<
                ScalarOf<C>,
                R,
            >>::mask()?)
            .register_bonding(<stages::query::Stage<C::HostCurve, R, L> as StageExt<
                ScalarOf<C>,
                R,
            >>::mask()?)
            .register_bonding(<stages::f::Stage<C::HostCurve, R, L> as StageExt<
                ScalarOf<C>,
                R,
            >>::mask()?)
            .register_bonding(<stages::eval::Stage<C::HostCurve, R, L> as StageExt<
                ScalarOf<C>,
                R,
            >>::mask()?);

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
        initial_internal_circuits + num_internal::<L>(),
        "internal circuit count mismatch"
    );

    Ok(registry)
}
