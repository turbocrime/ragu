//! The shared shape of a nested-side bridge stage: one host-curve point
//! carried as stage wires.
//!
//! Committing such a stage on the nested generators yields a point whose
//! coordinates are `CircuitField`, so the native side can witness it. Every
//! value that has to cross the curve boundary does so this way (see
//! [`super::f`], whose rx's wires *are* `native_f`).
//!
//! [`claim_bridge`](super::claim_bridge) and
//! [`challenge_bridge`](super::challenge_bridge) are both chains of this stage;
//! they differ only in what the carried point commits to and where the chain
//! attaches. Rather than duplicate the stage per family, [`Stage`] takes its
//! parent as a type parameter and each family is a chain of type aliases.

use core::marker::PhantomData;

use ragu_arithmetic::CurveAffine;
use ragu_circuits::{polynomials::Rank, staging::InducedStages};
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

/// Number of curve points in each bridge stage: one host commitment.
const NUM: usize = 1;

/// Wire width of a single bridge slot: one point, two coordinates.
///
/// Public because a run's layout can be rebuilt from its anchor plus this
/// width, which is how bridge geometry reaches code that cannot name the stage
/// types (see `StepCtx`).
pub const WIDTH: usize = NUM * 2;

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
        WIDTH
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

/// A whole family of [`Stage`] slots, spanning `L::len()` of them, chained
/// after `P`.
///
/// A family whose length is a property of the application cannot be a chain of
/// aliases — but it does not have to be. `Run` is the family's single entry in
/// the typed hierarchy: one ordinary [`Stage`](ragu_circuits::staging::Stage)
/// covering every slot's wires, with
/// [`InducedStages`] saying where the slot boundaries fall inside it.
///
/// This is exact rather than approximate. Each slot is [`NUM`] points, so
/// `2 * NUM` wires, so a whole number of gates with nothing wasted to padding;
/// a run of `L::len()` slots therefore spans precisely the gates that a chain
/// of `L::len()` aliases would have. Everything after the run — including the
/// circuit's [`Last`](ragu_circuits::staging::MultiStageCircuit::Last) stage —
/// chains onto `Run` and computes the same `skip_gates` it always did, with no
/// knowledge that the span is subdivided. `ragu_circuits`' own
/// `induced_run_matches_typed_chain` test pins that equivalence.
///
/// `L` carries the slot count as a type so the count stays a compile-time fact
/// even when it is not a literal — the escape hatch [`Len`] documents for
/// exactly this case.
pub struct Run<C, R, P, L> {
    _marker: PhantomData<(C, R, P, L)>,
}

impl<C, R, P, L> Default for Run<C, R, P, L> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C, R, P, L> Run<C, R, P, L>
where
    C: CurveAffine,
    R: Rank,
    P: ragu_circuits::staging::Stage<C::Base, R>,
    L: Len,
{
    /// The layout subdividing this run into its slots, anchored at the gate the
    /// run begins on.
    ///
    /// This is the only place the run's geometry is described twice — once as
    /// `Run`'s own `values()`, once as the slot widths here — and
    /// [`configure_induced`](ragu_circuits::staging::StageBuilder::configure_induced)
    /// rejects the pair if they disagree.
    pub fn layout() -> InducedStages {
        InducedStages::after::<C::Base, R, P>(alloc::vec![WIDTH; L::len()])
    }
}

impl<C: CurveAffine, R: Rank, P: ragu_circuits::staging::Stage<C::Base, R>, L: Len>
    ragu_circuits::staging::Stage<C::Base, R> for Run<C, R, P, L>
{
    type Parent = P;
    type Witness<'source> = &'source [C];
    type OutputKind = Kind![C::Base; FixedVec<Point<'_, _, C>, L>];

    fn values() -> usize {
        WIDTH * L::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let mut points = alloc::vec::Vec::with_capacity(L::len());
        for slot in 0..L::len() {
            points.push(Point::alloc(dr, witness.as_ref().map(|w| w[slot]))?);
        }

        FixedVec::new(points)
    }
}
