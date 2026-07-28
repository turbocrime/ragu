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
use ragu_primitives::{GadgetExt as _, Point, vec::Len};

use crate::internal::{
    endoscalar::{EndoscalarStage, Points, PointsStage},
    native::RxIndex,
    nested::{EndoscalingPointsLen, stages},
};

/// A cursor over [`PointsStage`] inputs that enforces equality against
/// corresponding bridge stage elements.
struct Walker<'pts, 'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, L: Len> {
    points: &'pts Points<'dr, D, C, L>,
    index: usize,
}

impl<'pts, 'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, L: Len> Walker<'pts, 'dr, D, C, L> {
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

/// Loading circuit that loads the entire nested stage hierarchy.
pub struct Circuit<C: CurveAffine, R: Rank, const POLYS: usize> {
    /// The current step's own shape (its bridge runs and eval stashes).
    own: crate::framework_hooks::HookLayout,
    /// The left child's shape.
    left: crate::framework_hooks::HookLayout,
    /// The right child's shape.
    right: crate::framework_hooks::HookLayout,
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank, const POLYS: usize> Circuit<C, R, POLYS> {
    pub fn new(
        own: crate::framework_hooks::HookLayout,
        left: crate::framework_hooks::HookLayout,
        right: crate::framework_hooks::HookLayout,
    ) -> Self {
        Self {
            own,
            left,
            right,
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank, const POLYS: usize> MultiStageCircuit<C::Base, R>
    for Circuit<C, R, POLYS>
{
    type Last = stages::claim_bridge::Run<C, R, POLYS>;
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
        let claim_layout =
            crate::internal::nested::claim_run_layout::<C, R>(self.own, self.left, self.right);

        // As in `copying`: every position comes from the value-level chain.
        let chain = crate::internal::nested::chain_layout::<C, R>(self.own, self.left, self.right);

        let dr = dr.skip_stage_sized(EndoscalarStage, chain.width(0))?;
        let (points_guard, dr) = dr.configure_stage_sized(
            PointsStage::<C, EndoscalingPointsLen<POLYS>>::default(),
            chain.width(1),
        )?;
        let (preamble_guard, dr) = dr.configure_stage_sized(
            stages::preamble::Stage::<C, R, POLYS>::default(),
            chain.width(2),
        )?;
        let (s_prime_guard, dr) = dr.configure_stage_sized(
            stages::s_prime::Stage::<C, R, POLYS>::default(),
            chain.width(3),
        )?;
        let (inner_error_guard, dr) = dr.configure_stage_sized(
            stages::inner_error::Stage::<C, R, POLYS>::default(),
            chain.width(4),
        )?;
        let dr = dr.skip_stage_sized(
            stages::outer_error::Stage::<C, R, POLYS>::default(),
            chain.width(5),
        )?;
        let (ab_guard, dr) =
            dr.configure_stage_sized(stages::ab::Stage::<C, R, POLYS>::default(), chain.width(6))?;
        let (query_guard, dr) = dr.configure_stage_sized(
            stages::query::Stage::<C, R, POLYS>::default(),
            chain.width(7),
        )?;
        let (f_guard, dr) =
            dr.configure_stage_sized(stages::f::Stage::<C, R, POLYS>::default(), chain.width(8))?;
        let (eval_guard, dr) = dr.configure_stage_sized(
            stages::eval::Stage::<C, R, POLYS>::default(),
            chain.width(9),
        )?;
        let (claim_guards, dr) = dr
            .configure_induced_sized::<stages::claim_bridge::Run<C, R, POLYS>, _>(
                stages::claim_bridge::Slot::<C, R>::default(),
                &claim_layout,
                claim_layout.skip_gates(0),
            )?;
        let dr = dr.finish();

        // Load stage gadgets. Witness values are never accessed — the circuit
        // only runs during `into_bonding_object` where MaybeKind = Empty.
        macro_rules! w {
            () => {
                _witness.as_ref().map(|_| unreachable!())
            };
        }
        let points = points_guard.unenforced(dr, w!())?;
        let preamble = preamble_guard.unenforced(dr, w!())?;
        let s_prime = s_prime_guard.unenforced(dr, w!())?;
        let inner_error = inner_error_guard.unenforced(dr, w!())?;
        let ab = ab_guard.unenforced(dr, w!())?;
        let query = query_guard.unenforced(dr, w!())?;
        let f_stage = f_guard.unenforced(dr, w!())?;
        let eval = eval_guard.unenforced(dr, w!())?;
        let claim_bridges = claim_guards
            .into_iter()
            .map(|guard| Ok(guard.unenforced(dr, w!())?.host))
            .collect::<Result<alloc::vec::Vec<_>>>()?;

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

        // Each poly-query claim's bridge stage must witness exactly the host
        // commitment this proof records for that slot. The stage's wires are
        // therefore the host point, so committing the stage (which yields the
        // claim's instance-bound `com`) binds `com` to that host commitment —
        // mirroring how `BridgeF.native_f` ties `bridge_f_commitment` above.
        assert_eq!(
            claim_bridges.len(),
            eval.claims.len(),
            "the claim-bridge run did not yield one slot per claim"
        );
        for (slot, bridge_host) in claim_bridges.iter().enumerate() {
            bridge_host.enforce_equal(dr, &eval.claims[slot])?;
        }

        Ok(WithAux::new((), D::unit()))
    }
}
