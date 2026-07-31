//! Per-claim bridge stages: one committed stage per poly-query claim slot.
//!
//! A poly-query claim's nested-curve commitment `com_i` is what the *step*
//! sees — its Fiat–Shamir challenges and header hashes are derived from it.
//! For `com_i` to be bound to the polynomial the parent actually folds, it must
//! be the commitment of a polynomial the proof carries, whose wires *are* the
//! claim's host commitment. That is exactly the shape of every other
//! cross-curve commitment in the framework (see [`super::f`], whose rx's wires
//! *are* `native_f`, tied to the endoscaling by the
//! [`loading`](super::super::circuits::loading) circuit).
//!
//! Each slot gets its own stage — and therefore its own commitment — because
//! a claim needs a per-polynomial handle; contrast [`super::eval`], which
//! deliberately commits all its slots at once as a single stashed copy.
//!
//! A step's own view of the host commitment — its four 128-bit limbs — does
//! not come from this stage. It comes from the claim-lift polynomial `q`
//! riding the accumulator: see
//! [`claim_lift_poly`](crate::internal::challenge::claim_lift_poly) and
//! [`StepCtx::poly_limbs`](crate::step::StepCtx::poly_limbs).
//!
//! ## Why this family is a run
//!
//! How many claim slots exist is a property of the application being built, not
//! of any Rust type, so this family cannot be a chain of per-slot aliases. It
//! is a [`crate::internal::Run`] of [`host_bridge::Stage`] instead: one stage in
//! the typed hierarchy spanning every slot, subdivided by a [`layout`] that says
//! where each slot's wires begin. [`host_bridge`] documents why that
//! subdivision is exact.
//!
//! Nothing downstream has to care: the run occupies the same gates an alias
//! chain would, and the loading circuit's `Last` is still an ordinary stage
//! type.

use ragu_arithmetic::CurveAffine;
use ragu_circuits::{polynomials::Rank, staging::InducedStages};
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{GadgetExt, Point};

use super::host_bridge;

/// The claim-bridge family: every slot, as one stage chained after
/// [`super::eval`].
///
/// How many slots there are is the application's poly capacity — a value, read
/// from [`layout`] — so it appears nowhere in this type.
pub type Run<C, R> = crate::internal::Run<C, R, super::eval::Stage<C, R>>;

/// The witness body for a single claim slot.
///
/// Its own chain position is unused — where a slot's wires land comes from
/// [`layout`], not from this type — so one type serves every slot.
pub type Slot<C, R> = host_bridge::Stage<C, R, ()>;

/// Enforces that a claim slot's wires name `host`.
///
/// The tie both [`loading`](super::super::circuits::loading) (for this proof's
/// own slots) and [`copying`](super::super::circuits::copying) (for a child's,
/// one generation up) make. One function, because the two must state the same
/// relation: a fuse establishes about its immediate children exactly what the
/// child's own proof establishes about itself.
///
/// A point equality — linear, so it is legal in the bonding circuits that are
/// the only callers.
pub(crate) fn enforce_names<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>>(
    dr: &mut D,
    bridge: &host_bridge::Output<'dr, D, C>,
    host: &Point<'dr, D, C>,
) -> Result<()> {
    bridge.host.enforce_equal(dr, host)
}

/// The layout subdividing [`Run`] into one slot per claim.
///
/// A free function taking `capacity`: its two callers —
/// `ProofBuilder::claim_bridge_rx` and `StepCtx::witness_polynomial`, which
/// runs during witnessing with no builder at all — must produce a
/// bit-identical commitment from different state. Builds only the claims run,
/// where `NestedLayouts::new` builds all four.
pub fn layout<C: CurveAffine, R: Rank>(polys: usize) -> InducedStages {
    use crate::internal::nested::{chain_layout, claim_run_layout};

    claim_run_layout::<C, R>(&chain_layout::<C, R>(polys), polys)
}

#[cfg(test)]
mod tests {
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        // Only the slot has a type-level width. The run's is the application's
        // poly capacity, so it is checked as a layout below, not as a `Stage`.
        assert_stage_values(&Slot::<EqAffine, R>::default());
    }

    /// The layout tiles the run: one slot per claim, each one gate (two
    /// wires) wide, anchored where the nested chain ends — at whatever
    /// capacity it is asked for, not at one blessed shape.
    #[test]
    fn layout_tiles_the_run() {
        for polys in [1, 3, 8] {
            let layout = layout::<EqAffine, R>(polys);

            assert_eq!(layout.len(), polys, "one slot per polynomial");
            assert_eq!(
                layout.skip_gates(0),
                crate::internal::nested::chain_layout::<EqAffine, R>(polys).final_skip_gates(),
                "the first slot does not start where the chain ends"
            );
            for slot in 0..polys {
                assert_eq!(
                    layout.skip_gates(slot),
                    layout.skip_gates(0) + slot,
                    "slot {slot} is not one gate past its predecessor"
                );
            }
        }
    }
}
