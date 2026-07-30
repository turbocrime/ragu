//! Preamble stage for nested fuse operations.
//!
//! Collects child proof commitments for cross-curve accumulation.

use alloc::vec::Vec;

use ragu_arithmetic::{CurveAffine, Cycle};
use ragu_circuits::polynomials::Rank;
use ragu_core::{Result, drivers::Driver, gadgets::Gadget};
use ragu_primitives::{Point, io::Write};

use crate::{
    Proof,
    internal::{endoscalar::PointsStage, native::RxIndex},
};

/// Number of curve points in this stage: the native preamble commitment plus,
/// per child, the `_10_p` components (one per [`RxIndex`] entry — plus `a`,
/// `b`, `registry_xy` and `p`) and the stashed poly-query claim commitments.
///
/// Both children present the application's capacity, so one value sizes both.
pub const fn num_points(polys: usize) -> usize {
    use crate::internal::nested::child_endoscaling_points;

    /// The leading slot [`Output::from_slots`] reads before either child's
    /// block. Not to be confused with the leading point of
    /// [`num_endoscaling_points`](crate::internal::nested::num_endoscaling_points),
    /// which is `f.commitment`.
    const NATIVE_PREAMBLE_SLOT: usize = 1;

    NATIVE_PREAMBLE_SLOT + 2 * child_endoscaling_points(polys)
}

/// This stage's wire width; the value-level source of the typed
/// [`values()`](ragu_circuits::staging::Stage::values).
pub const fn num_values(polys: usize) -> usize {
    num_points(polys) * 2
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

/// One child proof's **fixed** points in the preamble bridge stage, as the
/// circuit body names them.
///
/// A gadget, as on `main`: the derive places these seventeen wires from the field
/// list, so the field list is the one statement of their order. The child's
/// poly-query claims are **not** here — they are [`ChildStashedClaims`], their own
/// type from their own method, because their count is the application's poly
/// capacity and a gadget's width is fixed by its fields.
///
/// Field order is the leading slot order [`ChildWitness::slot_points`] emits and
/// [`child_from_slots`] consumes.
#[derive(Gadget, Write)]
pub struct ChildOutput<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    // Field order matches `_10_p` accumulation order.
    /// Point commitment from the child's application circuit.
    #[ragu(gadget)]
    pub application: Point<'dr, D, C>,
    /// Point commitment from the child's first hashes circuit.
    #[ragu(gadget)]
    pub hashes_1: Point<'dr, D, C>,
    /// Point commitment from the child's second hashes circuit.
    #[ragu(gadget)]
    pub hashes_2: Point<'dr, D, C>,
    /// Point commitment from the child's inner collapse circuit.
    #[ragu(gadget)]
    pub inner_collapse: Point<'dr, D, C>,
    /// Point commitment from the child's outer collapse circuit.
    #[ragu(gadget)]
    pub outer_collapse: Point<'dr, D, C>,
    /// Point commitment from the child's compute_v circuit.
    #[ragu(gadget)]
    pub compute_v: Point<'dr, D, C>,
    /// Point commitment from the child's challenge binding circuit.
    #[ragu(gadget)]
    pub challenge_binding: Point<'dr, D, C>,

    /// Stashed commitment from the child's preamble bridge stage.
    #[ragu(gadget)]
    pub stashed_preamble: Point<'dr, D, C>,
    /// Stashed commitment from the child's inner error bridge stage.
    #[ragu(gadget)]
    pub stashed_inner_error: Point<'dr, D, C>,
    /// Stashed commitment from the child's outer error bridge stage.
    #[ragu(gadget)]
    pub stashed_outer_error: Point<'dr, D, C>,
    /// Stashed commitment from the child's query bridge stage.
    #[ragu(gadget)]
    pub stashed_query: Point<'dr, D, C>,
    /// Stashed commitment from the child's eval bridge stage.
    #[ragu(gadget)]
    pub stashed_eval: Point<'dr, D, C>,
    /// Stashed commitment from the child's challenge-slot stage.
    #[ragu(gadget)]
    pub stashed_challenges: Point<'dr, D, C>,
    /// Stashed `a` commitment from the child's AB bridge stage.
    #[ragu(gadget)]
    pub stashed_ab_a: Point<'dr, D, C>,
    /// Stashed `b` commitment from the child's AB bridge stage.
    #[ragu(gadget)]
    pub stashed_ab_b: Point<'dr, D, C>,
    /// Stashed registry XY commitment from the child.
    #[ragu(gadget)]
    pub stashed_registry_xy: Point<'dr, D, C>,
    /// Stashed accumulated P commitment from the child.
    #[ragu(gadget)]
    pub stashed_p: Point<'dr, D, C>,
}

/// One child proof's stashed poly-query claim host commitments, in slot order.
///
/// One per polynomial the child witnessed — a count the application fixes, so a
/// value rather than a length in the type, which is exactly why this is its own
/// type and not a field of [`ChildOutput`]. Loading enforces these against the
/// [`PointsStage`] inputs (they enter the `_10_p` accumulation); copying verifies
/// them against the child's own eval bridge stage record.
pub struct ChildStashedClaims<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    pub claims: Vec<Point<'dr, D, C>>,
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

/// Pulls the next slot, or reports the run was short.
fn next_slot<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>>(
    slots: &mut impl Iterator<Item = Point<'dr, D, C>>,
) -> Result<Point<'dr, D, C>> {
    slots.next().ok_or_else(|| {
        ragu_core::Error::MalformedEncoding(
            "the preamble run yielded fewer slots than the layout sized it for".into(),
        )
    })
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> ChildOutput<'dr, D, C> {
    /// Rebuild the fixed block from the run's slots, in the order
    /// [`ChildWitness::slot_points`] emitted it.
    ///
    /// Takes no count: this block's width is the field list's, which is the point
    /// of it being a gadget.
    fn from_slots(slots: &mut impl Iterator<Item = Point<'dr, D, C>>) -> Result<Self> {
        Ok(ChildOutput {
            application: next_slot(slots)?,
            hashes_1: next_slot(slots)?,
            hashes_2: next_slot(slots)?,
            inner_collapse: next_slot(slots)?,
            outer_collapse: next_slot(slots)?,
            compute_v: next_slot(slots)?,
            challenge_binding: next_slot(slots)?,
            stashed_preamble: next_slot(slots)?,
            stashed_inner_error: next_slot(slots)?,
            stashed_outer_error: next_slot(slots)?,
            stashed_query: next_slot(slots)?,
            stashed_eval: next_slot(slots)?,
            stashed_challenges: next_slot(slots)?,
            stashed_ab_a: next_slot(slots)?,
            stashed_ab_b: next_slot(slots)?,
            stashed_registry_xy: next_slot(slots)?,
            stashed_p: next_slot(slots)?,
        })
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> ChildStashedClaims<'dr, D, C> {
    /// Rebuild this child's claim block from the run's slots, immediately after
    /// its fixed block.
    ///
    /// `polys` comes from the same layout that sized the run, so a mismatch is a
    /// short iterator, which is what
    /// [`MalformedEncoding`](ragu_core::Error::MalformedEncoding) reports.
    fn from_slots(
        slots: &mut impl Iterator<Item = Point<'dr, D, C>>,
        polys: usize,
    ) -> Result<Self> {
        Ok(ChildStashedClaims {
            claims: (0..polys)
                .map(|_| next_slot(slots))
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

/// The preamble bridge stage's fixed points, as the circuit body names them.
///
/// A gadget, as on `main`. The stage's claim blocks are [`StashedClaims`].
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// Point commitment from the native preamble stage.
    #[ragu(gadget)]
    pub native_preamble: Point<'dr, D, C>,
    /// Points from the left child proof.
    #[ragu(gadget)]
    pub left: ChildOutput<'dr, D, C>,
    /// Points from the right child proof.
    #[ragu(gadget)]
    pub right: ChildOutput<'dr, D, C>,
}

/// Both children's stashed claim blocks.
///
/// Mirrors [`Output`]'s left/right shape, separately, because the count is a
/// value.
pub struct StashedClaims<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    pub left: ChildStashedClaims<'dr, D, C>,
    pub right: ChildStashedClaims<'dr, D, C>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Output<'dr, D, C> {
    /// Rebuild both views from the run's slots, which the run places interleaved:
    /// `native_preamble`, the left child's fixed block, its claims, then the
    /// right child's fixed block and claims.
    ///
    /// The two halves come back as separate values because they are separate
    /// types; the interleaving is why one walk produces both rather than each
    /// reading the run independently.
    ///
    /// One `polys` sizes both children's blocks, because [`num_points`] measures
    /// the span the same way — `1 + 2 * child_endoscaling_points`. An asymmetric
    /// pair would mis-tile the run.
    pub fn from_slots(
        slots: impl IntoIterator<Item = Point<'dr, D, C>>,
        polys: usize,
    ) -> Result<(Self, StashedClaims<'dr, D, C>)> {
        let slots = &mut slots.into_iter();

        let native_preamble = next_slot(slots)?;
        let left = ChildOutput::from_slots(slots)?;
        let left_claims = ChildStashedClaims::from_slots(slots, polys)?;
        let right = ChildOutput::from_slots(slots)?;
        let right_claims = ChildStashedClaims::from_slots(slots, polys)?;

        Ok((
            Output {
                native_preamble,
                left,
                right,
            },
            StashedClaims {
                left: left_claims,
                right: right_claims,
            },
        ))
    }
}

/// This stage's slot count: one slot per point of [`num_points`].
pub const fn num_slots(polys: usize) -> usize {
    num_points(polys)
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
pub type Stage<C, R> = crate::internal::Run<C, R, PointsStage<C, R>>;

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
    use crate::internal::tests::{R, stage_wire_count};

    /// The run's total width is exactly its slots' — the span this stage
    /// occupies in the chain has to be what the subdivision tiles, or every
    /// stage after it starts at the wrong gate.
    #[test]
    fn num_values_matches_slots() {
        for polys in [0, 1, 4, 8] {
            assert_eq!(
                num_values(polys),
                num_slots(polys) * stage_wire_count(&Slot::<EqAffine, R>::default()),
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
                num_slots(polys),
                "polys={polys}"
            );
        }
    }
}
