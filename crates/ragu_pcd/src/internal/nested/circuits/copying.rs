//! Copying circuit for the nested section.
//!
//! Relates the current fuse step's preamble to the child proof's stages,
//! ensuring that child commitments stashed in
//! [`ChildWitness`](crate::internal::nested::stages::preamble::ChildWitness) match the
//! actual values committed in the child's bridge stages. One instance per
//! child proof ([`Side::Left`] and [`Side::Right`]).
//!
//! The copying circuit loads the child's bridge stages in its own trace
//! (no wire-position collision with loading, which loads the current
//! step's stages) and enforces equality between each `ChildWitness`
//! stash field and the corresponding child bridge stage field.

use core::marker::PhantomData;

use ragu_arithmetic::CurveAffine;
use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::GadgetExt as _;

use crate::internal::{
    Side,
    endoscalar::{EndoscalarStage, PointSlotStage, Points, PointsStage},
    nested::{EndoPoints, stages},
};

/// Copying circuit that relates the current preamble to a child's stages.
/// `L` is the application's poly count as a
/// [`Len`](ragu_primitives::vec::Len); a child exposes the same shape.
pub struct Circuit<C: CurveAffine, R: Rank, L: ragu_primitives::vec::Len> {
    side: Side,
    _marker: PhantomData<(C, R, L)>,
}

impl<C: CurveAffine, R: Rank, L: ragu_primitives::vec::Len> Circuit<C, R, L> {
    pub fn new(side: Side) -> Self {
        Self {
            side,
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank, L: ragu_primitives::vec::Len> MultiStageCircuit<C::Base, R>
    for Circuit<C, R, L>
{
    type Last = stages::eval::Stage<C, R, L>;
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = ();
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, ()>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        _witness: DriverValue<D, ()>,
    ) -> Result<WithAux<Bound<'dr, D, ()>, DriverValue<D, ()>>> {
        // Every stage is placed from the value-level chain, shape-free ones
        // included: one misplaced width misplaces every stage after it.
        use crate::internal::nested::{ChainStage, NestedLayouts};

        let layouts = NestedLayouts::new::<C, R, L>();

        let dr = dr.skip_stage_sized(EndoscalarStage, layouts.width(ChainStage::Endoscalar))?;
        let (point_guards, dr) = dr.configure_induced_sized::<PointsStage<C, EndoPoints<L>>, _>(
            PointSlotStage::<C, R>::default(),
            &layouts.points,
        )?;
        let (preamble_guards, dr) = dr
            .configure_induced_sized::<stages::preamble::Stage<C, R, L>, _>(
                stages::host_bridge::Slot::<C, R>::default(),
                &layouts.preamble,
            )?;
        let (s_prime_guard, dr) = dr.configure_stage_sized(
            stages::s_prime::Stage::<C, R, L>::default(),
            layouts.width(ChainStage::SPrime),
        )?;
        let (inner_error_guard, dr) = dr.configure_stage_sized(
            stages::inner_error::Stage::<C, R, L>::default(),
            layouts.width(ChainStage::InnerError),
        )?;
        let (outer_error_guard, dr) = dr.configure_stage_sized(
            stages::outer_error::Stage::<C, R, L>::default(),
            layouts.width(ChainStage::OuterError),
        )?;
        let (ab_guard, dr) = dr.configure_stage_sized(
            stages::ab::Stage::<C, R, L>::default(),
            layouts.width(ChainStage::Ab),
        )?;
        let (query_guard, dr) = dr.configure_stage_sized(
            stages::query::Stage::<C, R, L>::default(),
            layouts.width(ChainStage::Query),
        )?;
        let dr = dr.skip_stage_sized(
            stages::f::Stage::<C, R, L>::default(),
            layouts.width(ChainStage::F),
        )?;
        let (eval_guards, dr) = dr.configure_induced_sized::<stages::eval::Stage<C, R, L>, _>(
            stages::host_bridge::Slot::<C, R>::default(),
            &layouts.eval,
        )?;
        let dr = dr.finish();

        // Load stage gadgets. Witness values are never accessed — the circuit
        // only runs during `into_bonding_object` where MaybeKind = Empty.
        macro_rules! w {
            () => {
                _witness.as_ref().map(|_| unreachable!())
            };
        }
        let points = Points::<D, C, EndoPoints<L>>::from_slots(
            point_guards
                .into_iter()
                .map(|guard| Ok(guard.unenforced(dr, w!())?.point))
                .collect::<Result<alloc::vec::Vec<_>>>()?,
        )?;
        let preamble = stages::preamble::Output::<D, C, L>::from_slots(
            preamble_guards
                .into_iter()
                .map(|guard| Ok(guard.unenforced(dr, w!())?.host))
                .collect::<Result<alloc::vec::Vec<_>>>()?,
        )?;
        let s_prime = s_prime_guard.unenforced(dr, w!())?;
        let inner_error = inner_error_guard.unenforced(dr, w!())?;
        let outer_error = outer_error_guard.unenforced(dr, w!())?;
        let ab = ab_guard.unenforced(dr, w!())?;
        let query = query_guard.unenforced(dr, w!())?;
        let eval = stages::eval::Output::<D, C, L>::from_slots(
            eval_guards
                .into_iter()
                .map(|guard| Ok(guard.unenforced(dr, w!())?.host))
                .collect::<Result<alloc::vec::Vec<_>>>()?,
        )?;

        // Select the child corresponding to this circuit's side.
        let child = match self.side {
            Side::Left => &preamble.left,
            Side::Right => &preamble.right,
        };

        // Enforce that each ChildWitness stash field matches the
        // corresponding child bridge stage field.
        //
        // stashed_preamble: routes through this step's BridgeSPrime,
        // which was enforced by loading to equal
        // preamble.native_preamble at proof-generation time.
        child
            .stashed_preamble
            .enforce_equal(dr, &s_prime.stashed_preamble)?;
        child
            .stashed_inner_error
            .enforce_equal(dr, &inner_error.native_inner_error)?;
        child
            .stashed_outer_error
            .enforce_equal(dr, &outer_error.native_outer_error)?;
        child.stashed_ab_a.enforce_equal(dr, &ab.a)?;
        child.stashed_ab_b.enforce_equal(dr, &ab.b)?;
        child.stashed_query.enforce_equal(dr, &query.native_query)?;
        child
            .stashed_registry_xy
            .enforce_equal(dr, &query.registry_xy)?;
        child.stashed_eval.enforce_equal(dr, &eval.native_eval)?;

        // Poly-query claims: the stashed claim host commitments must match
        // the child's own record of them in its eval bridge stage.
        for (stashed_claim, child_claim) in child.stashed_claims.iter().zip(eval.claims.iter()) {
            stashed_claim.enforce_equal(dr, child_claim)?;
        }

        // P: the child's accumulated p commitment is the last interstitial
        // of the child's PointsStage.
        let last_interstitial = points
            .interstitials
            .last()
            .expect("NUM_ENDOSCALING_POINTS guarantees >= 1 interstitial");
        child.stashed_p.enforce_equal(dr, last_interstitial)?;

        Ok(WithAux::new((), D::unit()))
    }
}
