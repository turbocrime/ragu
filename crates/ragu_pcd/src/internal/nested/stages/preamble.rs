//! Preamble stage for nested fuse operations.
//!
//! Collects child proof commitments for cross-curve accumulation.

use alloc::vec::Vec;

use ragu_arithmetic::{CurveAffine, Cycle};
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Point,
    io::Write,
    vec::{FixedVec, Len},
};

use crate::{
    Proof,
    internal::{endoscalar::PointsStage, native::RxIndex, nested::EndoPoints},
};

/// Number of curve points in this stage: the native preamble commitment plus
/// one block per child. Both children present the application's capacity, so
/// one value sizes both.
pub const fn num_points(polys: usize) -> usize {
    use crate::internal::nested::child_endoscaling_points;

    /// The leading slot [`Output::from_slots`] reads before either child's
    /// block (not `f.commitment`).
    const NATIVE_PREAMBLE_SLOT: usize = 1;

    NATIVE_PREAMBLE_SLOT + 2 * child_endoscaling_points(polys)
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
    /// order; must contain exactly the stage's poly-slot count.
    pub stashed_claims: Vec<C>,
    /// Stashed commitment to the child's claim-coordinate polynomial `q` —
    /// one entry when the shape has polynomial slots, none otherwise.
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
            stashed_claims: (0..proof.claim_host_commitments().len())
                .map(|i| proof.claim_host_commitment(i))
                .collect(),
            stashed_q: if proof.claim_host_commitments().len() == 0 {
                Vec::new()
            } else {
                alloc::vec![crate::internal::challenge::claim_coord_commitment::<CC, R>(
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

/// One child proof's points in the preamble bridge stage, as the circuit body
/// names them. Field order is the slot order [`ChildWitness::slot_points`]
/// emits and [`from_slots`](Self::from_slots) consumes.
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
    /// Stashed poly-query claim host commitments from the child, in slot
    /// order after the named points — the order `_10_p` accumulates.
    #[ragu(gadget)]
    pub stashed_claims: FixedVec<Point<'dr, D, C>, L>,
    /// Stashed `C_q` — one point when the shape has polynomial slots, none
    /// otherwise, at its `_10_p` fold position after the claims.
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

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, L: Len> ChildOutput<'dr, D, C, L> {
    /// Allocates one child's block, in field order.
    fn alloc(dr: &mut D, witness: DriverValue<D, &ChildWitness<C>>) -> Result<Self> {
        Ok(ChildOutput {
            application: Point::alloc(dr, witness.as_ref().map(|w| w.application))?,
            hashes_1: Point::alloc(dr, witness.as_ref().map(|w| w.hashes_1))?,
            hashes_2: Point::alloc(dr, witness.as_ref().map(|w| w.hashes_2))?,
            inner_collapse: Point::alloc(dr, witness.as_ref().map(|w| w.inner_collapse))?,
            outer_collapse: Point::alloc(dr, witness.as_ref().map(|w| w.outer_collapse))?,
            compute_v: Point::alloc(dr, witness.as_ref().map(|w| w.compute_v))?,
            challenge_binding: Point::alloc(dr, witness.as_ref().map(|w| w.challenge_binding))?,
            stashed_preamble: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_preamble))?,
            stashed_inner_error: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_inner_error))?,
            stashed_outer_error: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_outer_error))?,
            stashed_query: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_query))?,
            stashed_eval: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_eval))?,
            stashed_challenges: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_challenges))?,
            stashed_ab_a: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_ab_a))?,
            stashed_ab_b: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_ab_b))?,
            stashed_registry_xy: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_registry_xy))?,
            stashed_p: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_p))?,
            stashed_claims: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.stashed_claims[i]))
            })?,
            stashed_q: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.stashed_q[i]))
            })?,
        })
    }

}

/// The preamble bridge stage's points, as the circuit body names them.
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

/// The preamble bridge stage: `native_preamble`, then each child's block.
pub struct Stage<C: CurveAffine, R, L> {
    _marker: core::marker::PhantomData<(C, R, L)>,
}

impl<C: CurveAffine, R, L> Default for Stage<C, R, L> {
    fn default() -> Self {
        Self {
            _marker: core::marker::PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank, L: Len> ragu_circuits::staging::Stage<C::Base, R>
    for Stage<C, R, L>
{
    type Parent = PointsStage<C, EndoPoints<L>>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _, C, L>];

    fn values() -> usize {
        num_points(L::len()) * 2
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Output {
            native_preamble: Point::alloc(dr, witness.as_ref().map(|w| w.native_preamble))?,
            left: ChildOutput::alloc(dr, witness.as_ref().map(|w| &w.left))?,
            right: ChildOutput::alloc(dr, witness.as_ref().map(|w| &w.right))?,
        })
    }
}

