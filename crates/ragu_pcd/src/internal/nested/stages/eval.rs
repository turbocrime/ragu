//! Eval stage for nested fuse operations.

use alloc::vec::Vec;

use ragu_arithmetic::CurveAffine;
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::Point;

/// This stage's wire width for a step of shape `own` (the *current* step's
/// slots, not a child's); the value-level source of the typed
/// [`values()`](ragu_circuits::staging::Stage::values).
pub const fn num_values(own: crate::framework_hooks::HookLayout) -> usize {
    2 * (1 + own.poly_query.polys)
}

/// Witness data for this bridge stage.
pub struct Witness<C: CurveAffine> {
    pub native_eval: C,
    /// The current step's poly-query claim host commitments, in slot order.
    /// Stashed here — in a transcript-bound bridge stage — so the *parent's*
    /// copying circuit can check its preamble's stashed claim commitments
    /// against this proof's own record of them.
    ///
    /// Must contain exactly the stage's poly-slot count; the stage body
    /// indexes it up to that count.
    pub claims: Vec<C>,
}

/// This stage's points, as the circuit body names them.
///
/// Deliberately **not** a gadget: [`Stage`] places these as an induced run of
/// one-point slots, so this struct never crosses a stage boundary as a unit —
/// which is what lets the step's poly count stay a value.
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    pub native_eval: Point<'dr, D, C>,
    /// The current step's poly-query claim host commitments, in slot order.
    pub claims: Vec<Point<'dr, D, C>>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Output<'dr, D, C> {
    /// Rebuild the named view from the run's slots: `native_eval`, then one
    /// slot per claim, in the order [`Witness::slot_points`] emitted them.
    pub fn from_slots(
        slots: impl IntoIterator<Item = Point<'dr, D, C>>,
        polys: usize,
    ) -> Result<Self> {
        let slots = &mut slots.into_iter();
        let mut next = || {
            slots.next().ok_or_else(|| {
                ragu_core::Error::MalformedEncoding(
                    "the eval run yielded fewer slots than the layout sized it for".into(),
                )
            })
        };

        Ok(Output {
            native_eval: next()?,
            claims: (0..polys).map(|_| next()).collect::<Result<Vec<_>>>()?,
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

/// This stage's slot count for a step of shape `own`: `native_eval`, then one
/// slot per poly-query claim.
pub const fn num_slots(own: crate::framework_hooks::HookLayout) -> usize {
    1 + own.poly_query.polys
}

/// The witness body for one slot of the run: a single host-curve point.
pub type Slot<C, R> = super::host_bridge::Stage<C, R, ()>;

/// The eval bridge, spanning one run of one-point slots.
///
/// How many claims there are is a property of the application, so the run's
/// width is a value (see [`num_values`]) and this type carries no slot count.
/// It holds the run's position in the `Parent` chain; the framework reaches
/// the layout and [`Slot`] instead, never this stage's own geometry.
///
/// The whole run is masked and committed as **one** stage, exactly as it was
/// when it held a fixed vector — the subdivision decides where wires land, not
/// how many commitments there are. That matters here: a per-slot commitment
/// would defeat the point of this stage, which is a *single* stashed copy the
/// parent's copying circuit can check (see [`super::claim_bridge`], which
/// deliberately does the opposite).
pub type Stage<C, R> = super::host_bridge::Run<C, R, super::f::Stage<C, R>>;

#[cfg(test)]
mod tests {
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, capacity_with_polys, stage_wire_count};

    /// The run's total width is exactly its slots' — the span this stage
    /// occupies in the chain has to be what the subdivision tiles, or the
    /// claim-bridge run after it starts at the wrong gate.
    #[test]
    fn num_values_matches_slots() {
        for polys in [0, 1, 4, 8] {
            let capacity = capacity_with_polys(polys);
            assert_eq!(
                num_values(capacity),
                num_slots(capacity) * stage_wire_count(&Slot::<EqAffine, R>::default()),
                "polys={polys}"
            );
        }
    }
}
