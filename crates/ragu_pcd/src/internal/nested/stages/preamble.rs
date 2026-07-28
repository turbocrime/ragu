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
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Point, io::Write};

use crate::{
    NUM_CHALLENGE_SLOTS, NUM_POLY_SLOTS, Proof,
    internal::{endoscalar::PointsStage, native::RxIndex, nested::EndoPoints},
    slot_vec::SlotVec,
};

/// Number of curve points in this stage for children of the given shapes:
/// the native preamble commitment plus, per child, the `_10_p` components
/// (one per [`RxIndex`] entry at the child's own challenge count — plus `a`,
/// `b`, `registry_xy` and `p`) and the stashed poly-query claim commitments
/// at the child's own poly count.
pub const fn num_points(
    left: crate::framework_hooks::HookLayout,
    right: crate::framework_hooks::HookLayout,
) -> usize {
    use crate::internal::nested::child_endoscaling_points;
    1 + child_endoscaling_points(left) + child_endoscaling_points(right)
}

/// This stage's wire width for children of the given shapes; the value-level
/// source of the typed [`values()`](ragu_circuits::staging::Stage::values).
pub const fn num_values(
    left: crate::framework_hooks::HookLayout,
    right: crate::framework_hooks::HookLayout,
) -> usize {
    num_points(left, right) * 2
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
    /// The child's challenge-stage host commitments, in slot order. These are
    /// [`RxIndex::ChallengeStage`] components, so they sit with the rest of the
    /// rx block — `loading` ties them to the endoscaling point list, `copying`
    /// ties them to the child's own record. Must contain exactly the stage's
    /// challenge-slot count; the stage body indexes it up to that count.
    pub stashed_challenge_stages: Vec<C>,
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
    /// child's own eval bridge stage record. Length disciplined like
    /// `stashed_challenge_stages`, at the stage's poly-slot count.
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
            stashed_challenge_stages: (0..NUM_CHALLENGE_SLOTS)
                .map(|i| proof.native_rx_commitment(RxIndex::ChallengeStage(i as u32)))
                .collect(),
            stashed_ab_a: proof.native_commitment(RxComponent::AbA),
            stashed_ab_b: proof.native_commitment(RxComponent::AbB),
            stashed_registry_xy: proof.native_registry_xy_commitment(),
            stashed_p: proof.native_p_commitment(),
            stashed_claims: (0..NUM_POLY_SLOTS)
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

/// Output gadget for a single child proof in the preamble bridge stage.
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
    /// The child's challenge-stage host commitments, in slot order.
    #[ragu(gadget)]
    pub stashed_challenge_stages: SlotVec<Point<'dr, D, C>>,
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
    /// order.
    #[ragu(gadget)]
    pub stashed_claims: SlotVec<Point<'dr, D, C>>,
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
            ChallengeStage(slot) => &self.stashed_challenge_stages[slot as usize],
        }
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> ChildOutput<'dr, D, C> {
    fn alloc(
        dr: &mut D,
        witness: DriverValue<D, &ChildWitness<C>>,
        num_polys: usize,
        num_challenges: usize,
    ) -> Result<Self> {
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
            stashed_challenge_stages: (0..num_challenges)
                .map(|i| Point::alloc(dr, witness.as_ref().map(|w| w.stashed_challenge_stages[i])))
                .collect::<Result<_>>()?,
            stashed_ab_a: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_ab_a))?,
            stashed_ab_b: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_ab_b))?,
            stashed_registry_xy: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_registry_xy))?,
            stashed_p: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_p))?,
            stashed_claims: (0..num_polys)
                .map(|i| Point::alloc(dr, witness.as_ref().map(|w| w.stashed_claims[i])))
                .collect::<Result<_>>()?,
        })
    }
}

/// Prover-internal output gadget for the preamble bridge stage.
///
/// This is stage communication data, not part of the circuit's public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// Point commitment from the native preamble stage.
    #[ragu(gadget)]
    pub native_preamble: Point<'dr, D, C>,
    /// Output gadget for the left child proof.
    #[ragu(gadget)]
    pub left: ChildOutput<'dr, D, C>,
    /// Output gadget for the right child proof.
    #[ragu(gadget)]
    pub right: ChildOutput<'dr, D, C>,
}

pub struct Stage<C: CurveAffine, R> {
    /// Number of poly-query claim slots each child carries.
    num_polys: usize,
    /// Number of challenge-stage slots each child carries.
    num_challenges: usize,
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R> Default for Stage<C, R> {
    fn default() -> Self {
        Stage {
            num_polys: NUM_POLY_SLOTS,
            num_challenges: NUM_CHALLENGE_SLOTS,
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R> {
    type Parent = PointsStage<C, EndoPoints>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _, C>];

    fn values() -> usize {
        num_values(
            crate::framework_hooks::HookLayout::padded(),
            crate::framework_hooks::HookLayout::padded(),
        )
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
            left: ChildOutput::alloc(
                dr,
                witness.as_ref().map(|w| &w.left),
                self.num_polys,
                self.num_challenges,
            )?,
            right: ChildOutput::alloc(
                dr,
                witness.as_ref().map(|w| &w.right),
                self.num_polys,
                self.num_challenges,
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<EqAffine, R>::default());
    }
}
