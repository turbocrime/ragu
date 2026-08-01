//! Loading circuit for the nested section.
//!
//! Loads [`PointsStage`] and bridge stages (`preamble`, `s_prime`,
//! `inner_error`, `ab`, `query`, `f`) and enforces equality for all
//! [`PointsStage`] positions: every input (matched against
//! [`ChildWitness`](crate::internal::nested::stages::preamble::ChildWitness)
//! stash fields and current-step bridge stage fields) plus `initial`
//! (matched against `BridgeF.native_f`). The accumulation walk mirrors
//! `compute_p` in `_10_p` so that correctness can be verified by visual
//! comparison.
//!
//! Also enforces: `BridgeSPrime.stashed_preamble` ==
//! `BridgePreamble.native_preamble`, stashing the current step's native
//! preamble so that a parent's [`copying`](super::copying) circuit can
//! read it from `BridgeSPrime` instead of `BridgePreamble` (avoiding a
//! wire-position collision).

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
use ragu_primitives::{GadgetExt as _, Point};

use crate::internal::{
    endoscalar::{EndoscalarStage, PointSlotStage, Points, PointsStage},
    native::RxIndex,
    nested::{EndoPoints, stages},
};

/// A cursor over [`PointsStage`] inputs that enforces equality against
/// corresponding bridge stage elements.
struct Walker<'pts, 'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, L: ragu_primitives::vec::Len>
{
    points: &'pts Points<'dr, D, C, L>,
    index: usize,
}

impl<'pts, 'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, L: ragu_primitives::vec::Len>
    Walker<'pts, 'dr, D, C, L>
{
    fn new(points: &'pts Points<'dr, D, C, L>) -> Self {
        Self { points, index: 0 }
    }

    /// Enforce that the current [`PointsStage`] input equals `point`.
    fn enforce_equal(&mut self, dr: &mut D, point: &Point<'dr, D, C>) -> Result<()> {
        self.points.inputs[self.index].enforce_equal(dr, point)?;
        self.index += 1;
        Ok(())
    }

    /// Assert that every [`PointsStage`] input has been enforced.
    fn finish(self) {
        assert_eq!(
            self.index,
            self.points.inputs.len(),
            "walker did not exhaust all PointsStage inputs"
        );
    }
}

/// Loading circuit that loads the entire nested stage hierarchy. `L` is the
/// application's poly count as a [`Len`](ragu_primitives::vec::Len) — the
/// only shape this circuit needs.
pub struct Circuit<C: CurveAffine, R: Rank, L: ragu_primitives::vec::Len> {
    _marker: PhantomData<(C, R, L)>,
}

impl<C: CurveAffine, R: Rank, L: ragu_primitives::vec::Len> Circuit<C, R, L> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank, L: ragu_primitives::vec::Len> Default for Circuit<C, R, L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: CurveAffine, R: Rank, L: ragu_primitives::vec::Len> MultiStageCircuit<C::Base, R>
    for Circuit<C, R, L>
{
    type Last = stages::f::Stage<C, R, L>;
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
        use crate::internal::nested::{ChainStage, NestedLayouts};

        // As in `copying`: every position comes from the value-level chain.
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
        let dr = dr.skip_stage_sized(
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
        let (f_guard, dr) = dr.configure_stage_sized(
            stages::f::Stage::<C, R, L>::default(),
            layouts.width(ChainStage::F),
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
        let ab = ab_guard.unenforced(dr, w!())?;
        let query = query_guard.unenforced(dr, w!())?;
        let f_stage = f_guard.unenforced(dr, w!())?;

        // Walk through PointsStage inputs, mirroring the accumulation order
        // in `compute_p` (_10_p.rs).
        let mut walker = Walker::new(&points);

        for child in [&preamble.left, &preamble.right] {
            for &id in &RxIndex::ALL {
                walker.enforce_equal(dr, &child[id])?;
            }
            walker.enforce_equal(dr, &child.stashed_ab_a)?;
            walker.enforce_equal(dr, &child.stashed_ab_b)?;
            walker.enforce_equal(dr, &child.stashed_registry_xy)?;
            walker.enforce_equal(dr, &child.stashed_p)?;
            for stashed_claim in child.stashed_claims.iter() {
                walker.enforce_equal(dr, stashed_claim)?;
            }
            for stashed_q in child.stashed_q.iter() {
                walker.enforce_equal(dr, stashed_q)?;
            }
        }

        walker.enforce_equal(dr, &s_prime.registry_wx0)?;
        walker.enforce_equal(dr, &s_prime.registry_wx1)?;
        walker.enforce_equal(dr, &inner_error.registry_wy)?;
        walker.enforce_equal(dr, &ab.a)?;
        walker.enforce_equal(dr, &ab.b)?;
        walker.enforce_equal(dr, &query.registry_xy)?;

        walker.finish();

        // Relay: the current step's native_preamble is stashed in
        // BridgeSPrime so that a future copying circuit can verify it
        // from the child's BridgeSPrime without BridgePreamble collision.
        s_prime
            .stashed_preamble
            .enforce_equal(dr, &preamble.native_preamble)?;

        // The initial point (f.commitment) must match BridgeF.native_f.
        points.initial.enforce_equal(dr, &f_stage.native_f)?;

        Ok(WithAux::new((), D::unit()))
    }
}
