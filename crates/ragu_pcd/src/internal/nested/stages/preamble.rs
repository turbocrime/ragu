//! Preamble stage for nested fuse operations.
//!
//! Collects child proof commitments for cross-curve accumulation.

use alloc::vec::Vec;

use ragu_arithmetic::{CurveAffine, Cycle};
use ragu_circuits::polynomials::Rank;
use ragu_core::{Result, drivers::Driver, gadgets::Gadget};
use ragu_primitives::{
    Point,
    io::Write,
    vec::{FixedVec, Len},
};

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
    /// Stashed commitment to the child's claim-lift polynomial `q` — one
    /// entry when the shape has polynomial slots, none otherwise.
    /// Deterministic from the child's recorded hosts, so computed here rather
    /// than read off the proof.
    pub stashed_q: Vec<C>,
}

impl<C: CurveAffine> ChildWitness<C> {
    /// Construct from a child proof's commitments.
    pub fn from_proof<CC: Cycle<HostCurve = C>, R: Rank>(
        params: &CC::Params,
        proof: &Proof<CC, R>,
    ) -> Result<Self> {
        use crate::internal::native::RxComponent;
        Ok(Self {
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
            stashed_q: if proof.claim_host_commitments().len() == 0 {
                Vec::new()
            } else {
                alloc::vec![crate::internal::challenge::claim_lift_commitment::<CC, R>(
                    params,
                    proof.claim_host_commitments(),
                )?]
            },
        })
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
/// A gadget, as on `main`: the derive places these wires from the field list, so
/// the field list is the one statement of their order.
///
/// The child's poly-query claims are the last field rather than a separate type.
/// `FixedVec`'s length is a [`Len`], so a member whose count is the application's
/// poly capacity is still a gadget member — which is what lets the whole block be
/// one derive instead of a struct plus a hand-written tail.
///
/// Field order is the slot order [`ChildWitness::slot_points`] emits and
/// [`from_slots`](Self::from_slots) consumes.
#[derive(Gadget, Write)]
pub struct ChildOutput<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, L: Len> {
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
    /// Stashed poly-query claim host commitments from the child, in slot order —
    /// one per polynomial it witnessed. Loading enforces these against the
    /// [`PointsStage`] inputs (they enter the `_10_p` accumulation); copying
    /// verifies them against the child's own eval bridge stage record.
    ///
    /// Ordered so the per-child block is the seventeen named points then the
    /// claims, which is the order `_10_p` accumulates.
    #[ragu(gadget)]
    pub stashed_claims: FixedVec<Point<'dr, D, C>, L>,
    /// Stashed commitment to the child's claim-lift polynomial `q` — one point
    /// when the shape has polynomial slots, none otherwise, at its `_10_p`
    /// fold position after the claims. Loading enforces it against the
    /// [`PointsStage`] inputs; the tie from `C_q` to the claim-bridge bits is
    /// the limb tie family's, and lands with it.
    #[ragu(gadget)]
    pub stashed_q: FixedVec<Point<'dr, D, C>, QStashLen<L>>,
}

/// One stashed `C_q` when the shape has polynomial slots, none otherwise —
/// [`q_slots`](crate::internal::nested::q_slots) at the type level.
pub struct QStashLen<L: Len>(core::marker::PhantomData<L>);

impl<L: Len> Len for QStashLen<L> {
    fn len() -> usize {
        crate::internal::nested::q_slots(L::len())
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, L: Len> core::ops::Index<RxIndex>
    for ChildOutput<'dr, D, C, L>
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
        points.extend_from_slice(&self.stashed_q);
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

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, L: Len> ChildOutput<'dr, D, C, L> {
    /// Rebuild one child's block from the run's slots, in the order
    /// [`ChildWitness::slot_points`] emitted it: the named points, then the
    /// claims.
    ///
    /// Takes no count: the named points' width is the field list's and the claim
    /// block's is `L`'s. A run shorter than that is what
    /// [`MalformedEncoding`](ragu_core::Error::MalformedEncoding) reports.
    fn from_slots(slots: &mut impl Iterator<Item = Point<'dr, D, C>>) -> Result<Self> {
        let application = next_slot(slots)?;
        let hashes_1 = next_slot(slots)?;
        let hashes_2 = next_slot(slots)?;
        let inner_collapse = next_slot(slots)?;
        let outer_collapse = next_slot(slots)?;
        let compute_v = next_slot(slots)?;
        let challenge_binding = next_slot(slots)?;
        let stashed_preamble = next_slot(slots)?;
        let stashed_inner_error = next_slot(slots)?;
        let stashed_outer_error = next_slot(slots)?;
        let stashed_query = next_slot(slots)?;
        let stashed_eval = next_slot(slots)?;
        let stashed_challenges = next_slot(slots)?;
        let stashed_ab_a = next_slot(slots)?;
        let stashed_ab_b = next_slot(slots)?;
        let stashed_registry_xy = next_slot(slots)?;
        let stashed_p = next_slot(slots)?;
        let stashed_claims = (0..L::len())
            .map(|_| next_slot(slots))
            .collect::<Result<Vec<_>>>()?;
        let stashed_q = (0..QStashLen::<L>::len())
            .map(|_| next_slot(slots))
            .collect::<Result<Vec<_>>>()?;

        Ok(ChildOutput {
            application,
            hashes_1,
            hashes_2,
            inner_collapse,
            outer_collapse,
            compute_v,
            challenge_binding,
            stashed_preamble,
            stashed_inner_error,
            stashed_outer_error,
            stashed_query,
            stashed_eval,
            stashed_challenges,
            stashed_ab_a,
            stashed_ab_b,
            stashed_registry_xy,
            stashed_p,
            stashed_claims: stashed_claims.try_into()?,
            stashed_q: stashed_q.try_into()?,
        })
    }
}

/// The preamble bridge stage's points, as the circuit body names them.
///
/// A gadget, as on `main`.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, L: Len> {
    /// Point commitment from the native preamble stage.
    #[ragu(gadget)]
    pub native_preamble: Point<'dr, D, C>,
    /// Points from the left child proof.
    #[ragu(gadget)]
    pub left: ChildOutput<'dr, D, C, L>,
    /// Points from the right child proof.
    #[ragu(gadget)]
    pub right: ChildOutput<'dr, D, C, L>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, L: Len> Output<'dr, D, C, L> {
    /// Rebuild the named view from the run's slots: `native_preamble`, then each
    /// child's block in turn.
    ///
    /// One `L` sizes both children's blocks, because [`num_points`] measures the
    /// span the same way — `1 + 2 * child_endoscaling_points`. An asymmetric pair
    /// would mis-tile the run.
    pub fn from_slots(slots: impl IntoIterator<Item = Point<'dr, D, C>>) -> Result<Self> {
        let slots = &mut slots.into_iter();

        Ok(Output {
            native_preamble: next_slot(slots)?,
            left: ChildOutput::from_slots(slots)?,
            right: ChildOutput::from_slots(slots)?,
        })
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
                stashed_q: alloc::vec![
                    EqAffine::default();
                    crate::internal::nested::q_slots(polys)
                ],
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
