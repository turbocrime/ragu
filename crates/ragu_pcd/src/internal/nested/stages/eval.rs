//! Eval stage for nested fuse operations.

use alloc::vec::Vec;

use ragu_arithmetic::CurveAffine;
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

/// Witness data for this bridge stage.
pub struct Witness<C: CurveAffine> {
    pub native_eval: C,
    /// The current step's poly-query claim host commitments, in slot order;
    /// must contain exactly the stage's poly-slot count.
    pub claims: Vec<C>,
}

/// This stage's points, as the circuit body names them. The wire order is
/// `native_eval` then one slot per claim — the order
/// [`Witness::slot_points`] emits.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, L: Len> {
    #[ragu(gadget)]
    pub native_eval: Point<'dr, D, C>,
    /// The current step's poly-query claim host commitments, in slot order.
    #[ragu(gadget)]
    pub claims: FixedVec<Point<'dr, D, C>, L>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, L: Len> Output<'dr, D, C, L> {
    /// Rebuild the named view from the run's slots, in the order
    /// [`Witness::slot_points`] emitted them.
    pub fn from_slots(slots: impl IntoIterator<Item = Point<'dr, D, C>>) -> Result<Self> {
        let slots = &mut slots.into_iter();
        let mut next = || {
            slots.next().ok_or_else(|| {
                ragu_core::Error::MalformedEncoding(
                    "the eval run yielded fewer slots than the layout sized it for".into(),
                )
            })
        };

        let native_eval = next()?;
        let claims = (0..L::len()).map(|_| next()).collect::<Result<Vec<_>>>()?;

        Ok(Output {
            native_eval,
            claims: claims.try_into()?,
        })
    }
}

impl<C: CurveAffine> Witness<C> {
    /// This stage's points in slot order — the flat list the run places, the
    /// list [`Output::from_slots`] reads back, and what the rx path feeds
    /// [`InducedStages::rx`](ragu_circuits::staging::InducedStages::rx).
    pub fn slot_points(&self) -> Vec<C> {
        let mut points = Vec::with_capacity(1 + self.claims.len());
        points.push(self.native_eval);
        points.extend_from_slice(&self.claims);
        points
    }
}

/// This stage's slot count at the application's declared `capacity`:
/// `native_eval`, then one slot per poly-query claim.
pub const fn num_slots(polys: usize) -> usize {
    1 + polys
}

/// The eval bridge stage: `native_eval`, then one slot per poly-query claim —
/// a single stashed copy the parent's copying circuit checks.
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
    type Parent = super::f::Stage<C, R, L>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _, C, L>];

    fn values() -> usize {
        2 * (1 + L::len())
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
            native_eval: Point::alloc(dr, witness.as_ref().map(|w| w.native_eval))?,
            claims: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.claims[i]))
            })?,
        })
    }
}

