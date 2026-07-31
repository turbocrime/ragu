//! Eval stage for nested fuse operations.

use alloc::vec::Vec;

use ragu_arithmetic::CurveAffine;
use ragu_core::{Result, drivers::Driver, gadgets::Gadget};
use ragu_primitives::{
    Point,
    io::Write,
    vec::{FixedVec, Len},
};

/// This stage's wire width at the application's declared `capacity`; the
/// value-level source of the typed
/// [`values()`](ragu_circuits::staging::Stage::values).
///
/// The slots this stage carries are the *current* step's, not a child's — but
/// the capacity is the same either way, being declared once per application, so
/// this takes the same value every other stage in the chain does.
pub const fn num_values(polys: usize) -> usize {
    2 * (1 + polys)
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
/// A gadget. The claim block is a field rather than a separate type:
/// `FixedVec`'s length is a [`Len`], so a member whose count is the
/// application's poly capacity is still a gadget member, and the derive states
/// the order of both parts once.
///
/// `claims` is last, so the wire order is `native_eval` then one slot per claim —
/// the order [`Witness::slot_points`] emits.
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
    ///
    /// Takes no count: the claim block's width comes from `L`.
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

/// The witness body for one slot of the run: a single host-curve point.
pub type Slot<C, R> = super::host_bridge::Stage<C, R, ()>;

/// The eval bridge, spanning one run of one-point slots.
///
/// How many claims there are is a property of the application, so the run's
/// width is a value (see [`num_values`]) and this type carries no slot count.
/// It holds the run's position in the `Parent` chain; the framework reaches
/// the layout and [`Slot`] instead, never this stage's own geometry.
///
/// The whole run is masked and committed as **one** stage — the subdivision
/// decides where wires land, not how many commitments there are. That matters
/// here: a per-slot commitment
/// would defeat the point of this stage, which is a *single* stashed copy the
/// parent's copying circuit can check (see [`super::claim_bridge`], which
/// deliberately does the opposite).
pub type Stage<C, R> = crate::internal::Run<C, R, super::f::Stage<C, R>>;

#[cfg(test)]
mod tests {
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, stage_wire_count};

    /// The run's total width is exactly its slots' — the span this stage
    /// occupies in the chain has to be what the subdivision tiles, or the
    /// claim-bridge run after it starts at the wrong gate.
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
