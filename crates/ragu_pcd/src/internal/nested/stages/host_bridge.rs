//! The shared shape of a nested-side bridge stage: one host-curve point
//! carried as stage wires, committed on the nested generators so the native
//! side can witness its coordinates. A run of `n` one-point slots spans
//! exactly the gates a chain of `n` aliases would
//! (`induced_run_matches_typed_chain` pins it).

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
pub struct Stage<C, R, P> {
    _marker: PhantomData<(C, R, P)>,
}

/// One slot of a bridge run: a bridge stage with no chain position of its
/// own — the run's layout supplies the position.
pub type Slot<C, R> = Stage<C, R, ()>;

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
