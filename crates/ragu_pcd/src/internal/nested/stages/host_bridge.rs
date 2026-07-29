//! The shared shape of a nested-side bridge stage: one host-curve point
//! carried as stage wires.
//!
//! Committing such a stage on the nested generators yields a point whose
//! coordinates are `CircuitField`, so the native side can witness it. Every
//! value that has to cross the curve boundary does so this way (see
//! [`super::f`], whose rx's wires *are* `native_f`).
//!
//! [`claim_bridge`](super::claim_bridge) is a run of this stage. [`Stage`]
//! takes its parent as a type parameter so a family can attach wherever it
//! needs to without the stage being duplicated per family.

use core::marker::PhantomData;

use ragu_arithmetic::CurveAffine;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Point, io::Write};

use crate::internal::shape_dependent_stage;

/// Number of curve points in each bridge stage: one host commitment.
const NUM: usize = 1;

/// Witness for a single bridge stage: the host-curve commitment it carries.
pub struct Witness<C: CurveAffine> {
    pub host: C,
}

/// Prover-internal output gadget for a bridge stage.
///
/// Stage communication data, not part of the circuit's public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub host: Point<'dr, D, C>,
}

/// A bridge stage carrying one host-curve point, chained after `P`.
///
/// The chain is expressed through the `Parent` associated type, which cannot be
/// computed from a const generic on stable Rust. A family whose length is fixed
/// by a Rust type writes itself as a chain of aliases over this; a family whose
/// length is a property of the application uses [`Run`] instead, and passes
/// this as the per-slot witness body with its chain position unused.
pub struct Stage<C, R, P> {
    _marker: PhantomData<(C, R, P)>,
}

impl<C, R, P> Clone for Stage<C, R, P> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<C, R, P> Default for Stage<C, R, P> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank, P: ragu_circuits::staging::Stage<C::Base, R>>
    ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R, P>
{
    type Parent = P;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _, C>];

    fn values() -> usize {
        NUM * 2
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
            host: Point::alloc(dr, witness.as_ref().map(|w| w.host))?,
        })
    }
}

/// A whole family of [`Stage`] slots chained after `P`.
///
/// A family whose length is a property of the application cannot be a chain of
/// aliases — but it does not have to be. `Run` is the family's single entry in
/// the typed hierarchy: one ordinary [`Stage`](ragu_circuits::staging::Stage)
/// covering every slot's wires, with
/// [`InducedStages`](ragu_circuits::staging::InducedStages) saying where the
/// slot boundaries fall inside it.
///
/// This is exact rather than approximate. Each slot is [`NUM`] points, so
/// `2 * NUM` wires, so a whole number of gates with nothing wasted to padding;
/// a run of `n` slots therefore spans precisely the gates that a chain of `n`
/// aliases would have. Everything after the run — including the circuit's
/// [`Last`](ragu_circuits::staging::MultiStageCircuit::Last) stage — chains
/// onto `Run` and computes the same `skip_gates` it always did, with no
/// knowledge that the span is subdivided. `ragu_circuits`' own
/// `induced_run_matches_typed_chain` test pins that equivalence.
///
/// # The run carries no slot count
///
/// `Run` exists only to occupy a position in the `Parent` chain.
/// [`configure_induced_sized`](ragu_circuits::staging::StageBuilder::configure_induced_sized)
/// reserves each slot from the *layout*, and each slot's wires are produced by
/// [`Stage`]; the run's own [`values`](ragu_circuits::staging::Stage::values),
/// [`OutputKind`](ragu_circuits::staging::Stage::OutputKind) and
/// [`witness`](ragu_circuits::staging::Stage::witness) are never reached. So
/// the slot count stays a value — it is a property of the application, which
/// is what [`shape_dependent_stage`] says — and downstream stages inherit no
/// parameter from it.
pub struct Run<C, R, P> {
    _marker: PhantomData<(C, R, P)>,
}

impl<C, R, P> Default for Run<C, R, P> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank, P: ragu_circuits::staging::Stage<C::Base, R>>
    ragu_circuits::staging::Stage<C::Base, R> for Run<C, R, P>
{
    type Parent = P;
    type Witness<'source> = &'source [C];
    type OutputKind = Kind![C::Base; Output<'_, _, C>];

    fn values() -> usize {
        shape_dependent_stage()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        _dr: &mut D,
        _witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        shape_dependent_stage()
    }
}
