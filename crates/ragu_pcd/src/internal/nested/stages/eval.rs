//! Eval stage for nested fuse operations.

use alloc::vec::Vec;

use ragu_arithmetic::CurveAffine;
use ragu_core::{Result, drivers::Driver, gadgets::Gadget};
use ragu_primitives::{Point, io::Write};

/// This stage's wire width at the application's declared `capacity`; the
/// value-level source of the typed
/// [`values()`](ragu_circuits::staging::Stage::values).
///
/// The slots this stage carries are the *current* step's, not a child's — but
/// the capacity is the same either way, being declared once per application, so
/// this takes the same value every other stage in the chain does.
pub const fn num_values(capacity: crate::framework_hooks::HookLayout) -> usize {
    2 * (1 + capacity.poly_query.polys)
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

/// This stage's fixed point, as the circuit body names it.
///
/// A gadget, exactly as on `main`: one named point, its wire order stated once by
/// the field list. The stage's dynamic tail is **not** part of this type — see
/// [`StashedClaims`], which comes from its own method and is its own type
/// precisely because its length is a value rather than a property of the type.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub native_eval: Point<'dr, D, C>,
}

/// The stage's dynamic tail: the current step's poly-query claim host
/// commitments, in slot order.
///
/// Deliberately not a gadget and deliberately not a field of [`Output`]. Its
/// length is the application's poly capacity — a value — and a gadget's wire
/// count is fixed by its field list, so the two cannot be one type without
/// pushing the poly count into the type system as far as
/// [`Proof`](crate::Proof). Keeping it separate is what lets [`Output`] keep its
/// derive.
pub struct StashedClaims<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    pub claims: Vec<Point<'dr, D, C>>,
}

/// Pulls the next slot, or reports the run was short.
fn next_slot<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>>(
    slots: &mut impl Iterator<Item = Point<'dr, D, C>>,
) -> Result<Point<'dr, D, C>> {
    slots.next().ok_or_else(|| {
        ragu_core::Error::MalformedEncoding(
            "the eval run yielded fewer slots than the layout sized it for".into(),
        )
    })
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Output<'dr, D, C> {
    /// Rebuild the fixed point from the run's leading slot, and the dynamic tail
    /// that follows it, in the order [`Witness::slot_points`] emitted them.
    ///
    /// Returns the two as separate values because they are separate types; one
    /// walk produces both because they share the run.
    pub fn from_slots(
        slots: impl IntoIterator<Item = Point<'dr, D, C>>,
        polys: usize,
    ) -> Result<(Self, StashedClaims<'dr, D, C>)> {
        let slots = &mut slots.into_iter();

        let native_eval = next_slot(slots)?;
        let claims = StashedClaims::from_slots(slots, polys)?;

        Ok((Output { native_eval }, claims))
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> StashedClaims<'dr, D, C> {
    /// Rebuild the claim block from the run's slots, after the fixed point.
    fn from_slots(
        slots: &mut impl Iterator<Item = Point<'dr, D, C>>,
        polys: usize,
    ) -> Result<Self> {
        Ok(StashedClaims {
            claims: (0..polys)
                .map(|_| next_slot(slots))
                .collect::<Result<Vec<_>>>()?,
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
pub const fn num_slots(capacity: crate::framework_hooks::HookLayout) -> usize {
    1 + capacity.poly_query.polys
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
pub type Stage<C, R> = crate::internal::Run<C, R, super::f::Stage<C, R>>;

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
