//! Preamble stage for nested fuse operations.
//!
//! Collects child proof commitments for cross-curve accumulation.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_arithmetic::{CurveAffine, Cycle};
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
};
use ragu_primitives::Point;

use crate::{
    Proof,
    internal::{endoscalar::PointsStage, native::RxIndex},
};

/// Number of curve points in this stage: the native preamble commitment plus,
/// per child, the `_10_p` components (one per [`RxIndex`] entry — plus `a`,
/// `b`, `registry_xy` and `p`) and the stashed poly-query claim commitments.
///
/// Both children present the application's capacity, so one value sizes both.
pub const fn num_points(capacity: crate::framework_hooks::HookLayout) -> usize {
    use crate::internal::nested::child_endoscaling_points;
    1 + 2 * child_endoscaling_points(capacity)
}

/// This stage's wire width; the value-level source of the typed
/// [`values()`](ragu_circuits::staging::Stage::values).
pub const fn num_values(capacity: crate::framework_hooks::HookLayout) -> usize {
    num_points(capacity) * 2
}

/// Witness data for a single child proof in the preamble bridge stage.
///
/// The initial fields (application through compute_v) are the primary
/// introduction of child circuit commitments into the nested transcript.
/// The remaining `stashed_*` fields are copies of values that already
/// exist in the child's unified instance or bridge stages, placed here
/// so that loading can enforce them against [`PointsStage`] and copying
/// can verify them against the child's bridge stage content.
#[derive(Clone)]
pub struct ChildWitness<C: CurveAffine> {
    // Field order matches the `_10_p` accumulation order.
    /// Commitment from the child's application circuit.
    pub application: C,
    /// Commitment from the child's first hashes circuit.
    pub hashes_1: C,
    /// Commitment from the child's second hashes circuit.
    pub hashes_2: C,
    /// Commitment from the child's inner collapse circuit.
    pub inner_collapse: C,
    /// Commitment from the child's outer collapse circuit.
    pub outer_collapse: C,
    /// Commitment from the child's compute_v circuit.
    pub compute_v: C,
    /// Commitment from the child's challenge binding circuit.
    pub challenge_binding: C,

    /// Stashed commitment from the child's preamble bridge stage.
    pub stashed_preamble: C,
    /// Stashed commitment from the child's inner error bridge stage.
    pub stashed_inner_error: C,
    /// Stashed commitment from the child's outer error bridge stage.
    pub stashed_outer_error: C,
    /// Stashed commitment from the child's query bridge stage.
    pub stashed_query: C,
    /// Stashed commitment from the child's eval bridge stage.
    pub stashed_eval: C,
    /// Stashed commitment from the child's challenge-slot stage.
    pub stashed_challenges: C,
    /// Stashed `a` commitment from the child's AB bridge stage.
    pub stashed_ab_a: C,
    /// Stashed `b` commitment from the child's AB bridge stage.
    pub stashed_ab_b: C,
    /// Stashed registry XY commitment from the child.
    pub stashed_registry_xy: C,
    /// Stashed accumulated P commitment from the child.
    pub stashed_p: C,
    /// Stashed poly-query claim host commitments from the child, in slot
    /// order. Loading enforces these against the [`PointsStage`] inputs (they
    /// enter the `_10_p` accumulation); copying verifies them against the
    /// child's own eval bridge stage record. Must contain exactly the stage's
    /// poly-slot count; the stage body indexes it up to that count.
    pub stashed_claims: Vec<C>,
}

impl<C: CurveAffine> ChildWitness<C> {
    /// Construct from a child proof's commitments.
    pub fn from_proof<CC: Cycle<HostCurve = C>, R: Rank>(proof: &Proof<CC, R>) -> Self {
        use crate::internal::native::RxComponent;
        Self {
            application: proof.native_rx_commitment(RxIndex::Application),
            hashes_1: proof.native_rx_commitment(RxIndex::Hashes1),
            hashes_2: proof.native_rx_commitment(RxIndex::Hashes2),
            inner_collapse: proof.native_rx_commitment(RxIndex::InnerCollapse),
            outer_collapse: proof.native_rx_commitment(RxIndex::OuterCollapse),
            compute_v: proof.native_rx_commitment(RxIndex::ComputeV),
            challenge_binding: proof.native_rx_commitment(RxIndex::ChallengeBinding),
            stashed_preamble: proof.native_rx_commitment(RxIndex::Preamble),
            stashed_inner_error: proof.native_rx_commitment(RxIndex::InnerError),
            stashed_outer_error: proof.native_rx_commitment(RxIndex::OuterError),
            stashed_query: proof.native_rx_commitment(RxIndex::Query),
            stashed_eval: proof.native_rx_commitment(RxIndex::Eval),
            stashed_challenges: proof.native_rx_commitment(RxIndex::Challenges),
            stashed_ab_a: proof.native_commitment(RxComponent::AbA),
            stashed_ab_b: proof.native_commitment(RxComponent::AbB),
            stashed_registry_xy: proof.native_registry_xy_commitment(),
            stashed_p: proof.native_p_commitment(),
            stashed_claims: (0..proof.application_polys().len())
                .map(|i| proof.claim_host_commitment(i))
                .collect(),
        }
    }
}

/// Witness data for the preamble bridge stage.
pub struct Witness<C: CurveAffine> {
    /// Commitment from the native preamble stage.
    pub native_preamble: C,
    /// Witness data from the left child proof.
    pub left: ChildWitness<C>,
    /// Witness data from the right child proof.
    pub right: ChildWitness<C>,
}

/// One child proof's points in the preamble bridge stage, as the circuit body
/// names them.
///
/// Deliberately **not** a gadget. The stage places its points as an induced run
/// of one-point slots, so this struct never crosses a stage boundary as a unit
/// — which is what lets `stashed_claims` be an ordinary [`Vec`] while the
/// sixteen fixed points keep their names. The child's poly count stays a value.
///
/// Field order is the slot order [`ChildWitness::slot_points`] emits and
/// [`from_slots`](Self::from_slots) consumes. All three are one list; changing
/// one without the others silently moves wires.
pub struct ChildOutput<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    // Field order matches `_10_p` accumulation order.
    /// Point commitment from the child's application circuit.
    pub application: Point<'dr, D, C>,
    /// Point commitment from the child's first hashes circuit.
    pub hashes_1: Point<'dr, D, C>,
    /// Point commitment from the child's second hashes circuit.
    pub hashes_2: Point<'dr, D, C>,
    /// Point commitment from the child's inner collapse circuit.
    pub inner_collapse: Point<'dr, D, C>,
    /// Point commitment from the child's outer collapse circuit.
    pub outer_collapse: Point<'dr, D, C>,
    /// Point commitment from the child's compute_v circuit.
    pub compute_v: Point<'dr, D, C>,
    /// Point commitment from the child's challenge binding circuit.
    pub challenge_binding: Point<'dr, D, C>,

    /// Stashed commitment from the child's preamble bridge stage.
    pub stashed_preamble: Point<'dr, D, C>,
    /// Stashed commitment from the child's inner error bridge stage.
    pub stashed_inner_error: Point<'dr, D, C>,
    /// Stashed commitment from the child's outer error bridge stage.
    pub stashed_outer_error: Point<'dr, D, C>,
    /// Stashed commitment from the child's query bridge stage.
    pub stashed_query: Point<'dr, D, C>,
    /// Stashed commitment from the child's eval bridge stage.
    pub stashed_eval: Point<'dr, D, C>,
    /// Stashed commitment from the child's challenge-slot stage.
    pub stashed_challenges: Point<'dr, D, C>,
    /// Stashed `a` commitment from the child's AB bridge stage.
    pub stashed_ab_a: Point<'dr, D, C>,
    /// Stashed `b` commitment from the child's AB bridge stage.
    pub stashed_ab_b: Point<'dr, D, C>,
    /// Stashed registry XY commitment from the child.
    pub stashed_registry_xy: Point<'dr, D, C>,
    /// Stashed accumulated P commitment from the child.
    pub stashed_p: Point<'dr, D, C>,
    /// Stashed poly-query claim host commitments from the child, in slot
    /// order. One per polynomial the child witnessed — a count the application
    /// fixes, so a `Vec` rather than a length in the type.
    pub stashed_claims: Vec<Point<'dr, D, C>>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> core::ops::Index<RxIndex>
    for ChildOutput<'dr, D, C>
{
    type Output = Point<'dr, D, C>;

    fn index(&self, idx: RxIndex) -> &Point<'dr, D, C> {
        use RxIndex::*;
        match idx {
            Application => &self.application,
            Hashes1 => &self.hashes_1,
            Hashes2 => &self.hashes_2,
            InnerCollapse => &self.inner_collapse,
            OuterCollapse => &self.outer_collapse,
            ComputeV => &self.compute_v,
            ChallengeBinding => &self.challenge_binding,
            Preamble => &self.stashed_preamble,
            InnerError => &self.stashed_inner_error,
            OuterError => &self.stashed_outer_error,
            Query => &self.stashed_query,
            Eval => &self.stashed_eval,
            Challenges => &self.stashed_challenges,
        }
    }
}

impl<C: CurveAffine> ChildWitness<C> {
    /// This child's points in slot order — the flat list the run places, and
    /// the order [`ChildOutput::from_slots`] reads them back in.
    fn slot_points(&self) -> Vec<C> {
        let mut points = alloc::vec![
            self.application,
            self.hashes_1,
            self.hashes_2,
            self.inner_collapse,
            self.outer_collapse,
            self.compute_v,
            self.challenge_binding,
            self.stashed_preamble,
            self.stashed_inner_error,
            self.stashed_outer_error,
            self.stashed_query,
            self.stashed_eval,
            self.stashed_challenges,
            self.stashed_ab_a,
            self.stashed_ab_b,
            self.stashed_registry_xy,
            self.stashed_p,
        ];
        points.extend_from_slice(&self.stashed_claims);
        points
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> ChildOutput<'dr, D, C> {
    /// Rebuild the named view from the run's slots, in the order
    /// [`ChildWitness::slot_points`] emitted them.
    ///
    /// `polys` is how many claim slots follow the sixteen fixed points. It
    /// comes from the same layout that sized the run, so a mismatch is a
    /// short iterator, which is what
    /// [`MalformedEncoding`](ragu_core::Error::MalformedEncoding) reports.
    fn from_slots(
        slots: &mut impl Iterator<Item = Point<'dr, D, C>>,
        polys: usize,
    ) -> Result<Self> {
        let mut next = || {
            slots.next().ok_or_else(|| {
                ragu_core::Error::MalformedEncoding(
                    "the preamble run yielded fewer slots than the layout sized it for".into(),
                )
            })
        };

        Ok(ChildOutput {
            application: next()?,
            hashes_1: next()?,
            hashes_2: next()?,
            inner_collapse: next()?,
            outer_collapse: next()?,
            compute_v: next()?,
            challenge_binding: next()?,
            stashed_preamble: next()?,
            stashed_inner_error: next()?,
            stashed_outer_error: next()?,
            stashed_query: next()?,
            stashed_eval: next()?,
            stashed_challenges: next()?,
            stashed_ab_a: next()?,
            stashed_ab_b: next()?,
            stashed_registry_xy: next()?,
            stashed_p: next()?,
            stashed_claims: (0..polys).map(|_| next()).collect::<Result<Vec<_>>>()?,
        })
    }
}

/// The preamble bridge stage's points, as the circuit body names them.
///
/// Stage communication data, not part of the circuit's public instance, and —
/// like [`ChildOutput`] — not a gadget: the body assembles it from the run's
/// slots.
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// Point commitment from the native preamble stage.
    pub native_preamble: Point<'dr, D, C>,
    /// Points from the left child proof.
    pub left: ChildOutput<'dr, D, C>,
    /// Points from the right child proof.
    pub right: ChildOutput<'dr, D, C>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Output<'dr, D, C> {
    /// Rebuild the named view from the run's slots: `native_preamble`, then
    /// the left child's block, then the right child's.
    ///
    /// Each child's block is sized by *its own* poly count, matching how
    /// [`num_points`] measures the span — the two children need not be the
    /// same shape.
    pub fn from_slots(
        slots: impl IntoIterator<Item = Point<'dr, D, C>>,
        left_polys: usize,
        right_polys: usize,
    ) -> Result<Self> {
        let slots = &mut slots.into_iter();
        Ok(Output {
            native_preamble: slots.next().ok_or_else(|| {
                ragu_core::Error::MalformedEncoding("the preamble run yielded no slots".into())
            })?,
            left: ChildOutput::from_slots(slots, left_polys)?,
            right: ChildOutput::from_slots(slots, right_polys)?,
        })
    }
}

/// This stage's slot count: one slot per point of [`num_points`].
pub const fn num_slots(capacity: crate::framework_hooks::HookLayout) -> usize {
    num_points(capacity)
}

/// The witness body for one slot of the run: a single host-curve point.
///
/// Its own chain position is unused — where a slot's wires land comes from the
/// layout, not from this type — so one type serves every point in the stage.
pub type Slot<C, R> = super::host_bridge::Stage<C, R, ()>;

/// The preamble bridge, spanning one run of one-point slots.
///
/// How many points there are depends on the children's poly counts, which is a
/// property of the application, so the run's width is a value (see
/// [`num_values`]) and this type carries no slot count. It exists to hold the
/// run's position in the `Parent` chain; the framework reaches the layout and
/// [`Slot`] instead, never this stage's own geometry.
///
/// The whole run is masked and committed as **one** stage, exactly as it was
/// when it held a fixed vector — the subdivision decides where wires land, not
/// how many commitments there are.
pub struct Stage<C: CurveAffine, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R> Default for Stage<C, R> {
    fn default() -> Self {
        Stage {
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R> {
    type Parent = PointsStage<C, R>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; super::host_bridge::Output<'_, _, C>];

    fn values() -> usize {
        crate::internal::shape_dependent_stage()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        _dr: &mut D,
        _witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        crate::internal::shape_dependent_stage()
    }
}

impl<C: CurveAffine> Witness<C> {
    /// This stage's points in slot order — the flat list the run places, and
    /// the list [`Output::from_slots`] reads back.
    ///
    /// This is also what the rx path feeds
    /// [`InducedStages::rx`](ragu_circuits::staging::InducedStages::rx), so the
    /// order here is the wire order the commitment covers.
    pub fn slot_points(&self) -> Vec<C> {
        let mut points = alloc::vec![self.native_preamble];
        points.extend(self.left.slot_points());
        points.extend(self.right.slot_points());
        points
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, capacity_with_polys, stage_wire_count};

    /// The run's total width is exactly its slots' — the span this stage
    /// occupies in the chain has to be what the subdivision tiles, or every
    /// stage after it starts at the wrong gate.
    #[test]
    fn num_values_matches_slots() {
        for polys in [0, 1, 4, 8] {
            let capacity = capacity_with_polys(polys);
            assert_eq!(
                num_values(capacity),
                num_slots(capacity) * stage_wire_count(&Slot::<EqAffine, R>::default()),
                "polys={polys}"
            );
        }
    }

    /// The witness emits exactly the slots the layout sizes, and
    /// `Output::from_slots` reads back exactly that many. These two orders are
    /// the same list stated twice; this is what pins them together.
    #[test]
    fn slot_points_matches_slot_count() {
        for polys in [0, 1, 4, 8] {
            let capacity = capacity_with_polys(polys);
            let child = ChildWitness::<EqAffine> {
                application: EqAffine::default(),
                hashes_1: EqAffine::default(),
                hashes_2: EqAffine::default(),
                inner_collapse: EqAffine::default(),
                outer_collapse: EqAffine::default(),
                compute_v: EqAffine::default(),
                challenge_binding: EqAffine::default(),
                stashed_preamble: EqAffine::default(),
                stashed_inner_error: EqAffine::default(),
                stashed_outer_error: EqAffine::default(),
                stashed_query: EqAffine::default(),
                stashed_eval: EqAffine::default(),
                stashed_challenges: EqAffine::default(),
                stashed_ab_a: EqAffine::default(),
                stashed_ab_b: EqAffine::default(),
                stashed_registry_xy: EqAffine::default(),
                stashed_p: EqAffine::default(),
                stashed_claims: alloc::vec![EqAffine::default(); polys],
            };
            let witness = Witness {
                native_preamble: EqAffine::default(),
                left: child.clone(),
                right: child,
            };

            assert_eq!(
                witness.slot_points().len(),
                num_slots(capacity),
                "polys={polys}"
            );
        }
    }
}
