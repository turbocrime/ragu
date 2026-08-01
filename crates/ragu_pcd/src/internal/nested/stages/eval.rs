//! Eval stage for nested fuse operations.

use alloc::vec::Vec;

use ragu_arithmetic::CurveAffine;
use ragu_core::{Result, drivers::Driver, gadgets::Gadget};
use ragu_primitives::{
    Point,
    io::Write,
    vec::{FixedVec, Len},
};

/// This stage's wire width at the application's declared capacity; the
/// value-level source of the typed
/// [`values()`](ragu_circuits::staging::Stage::values).
pub const fn num_values(polys: usize) -> usize {
    2 * (1 + polys)
}

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

/// The eval bridge, spanning one run of one-point slots. The run's width is a
/// value ([`num_values`]), and the whole run is masked and committed as
/// **one** stage — a single stashed copy the parent's copying circuit checks.
pub type Stage<C, R> = crate::internal::Run<C, R, super::f::Stage<C, R>>;

#[cfg(test)]
mod tests {
    use ragu_pasta::EqAffine;

    use super::{super::host_bridge::Slot, *};
    use crate::internal::tests::{R, stage_wire_count};

    /// The stage's chain span must be exactly what the subdivision tiles.
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
}
