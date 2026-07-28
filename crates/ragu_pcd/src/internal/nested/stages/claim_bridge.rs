//! Per-claim bridge stages: one committed stage per poly-query claim slot.
//!
//! A poly-query claim's nested-curve commitment `com_i` is what the *step*
//! sees — its Fiat–Shamir challenges and header hashes are derived from it.
//! For `com_i` to be bound to the polynomial the parent actually folds, it must
//! be the commitment of a polynomial the proof carries, whose wires are the
//! claim's host commitment. That is exactly the shape of every other
//! cross-curve commitment in the framework (see [`super::f`], whose rx's wires
//! *are* `native_f`, tied to the endoscaling by the
//! [`loading`](super::super::circuits::loading) circuit).
//!
//! Each slot gets its own stage — and therefore its own commitment — because
//! the consumer needs a per-polynomial handle. Committing all slots in one
//! stage (as [`super::eval`] does for its stashed copies) would yield a single
//! commitment that cannot identify an individual claim.
//!
//! ## Why this family is a run
//!
//! How many claim slots exist is a property of the application being built, not
//! of any Rust type, so this family cannot be a chain of per-slot aliases. It
//! is a [`host_bridge::Run`] instead: one stage in the typed hierarchy spanning
//! every slot, subdivided by a [`layout`] that says where each slot's wires
//! begin.
//!
//! Nothing downstream has to care: the run occupies the same gates an alias
//! chain would, and the loading circuit's `Last` is still an ordinary stage
//! type.

use ragu_arithmetic::CurveAffine;
use ragu_circuits::{polynomials::Rank, staging::InducedStages};
use ragu_primitives::vec::Len;

use super::host_bridge;

/// The claim-slot count the *typed* [`Run`] would need, which no type knows.
///
/// The real count is the application's poly capacity, which every
/// construction takes as a value through [`layout`]. See
/// [`shape_dependent_stage`](crate::internal::shape_dependent_stage).
pub struct Slots;

impl Len for Slots {
    fn len() -> usize {
        crate::internal::shape_dependent_stage()
    }
}

/// The claim-bridge family: every slot, as one stage chained after
/// [`super::eval`].
pub type Run<C, R> = host_bridge::Run<C, R, super::eval::Stage<C, R>, Slots>;

/// The witness body for a single claim slot.
///
/// Its own chain position is unused — where a slot's wires land comes from
/// [`layout`], not from this type — so one type serves every slot.
pub type Slot<C, R> = host_bridge::Stage<C, R, ()>;

/// The layout subdividing [`Run`] into one slot per claim.
pub fn layout<C: CurveAffine, R: Rank>(
    capacity: crate::framework_hooks::HookLayout,
) -> InducedStages {
    crate::internal::nested::claim_run_layout::<C, R>(capacity, capacity, capacity)
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

    /// The layout tiles the run: one slot per claim, each two gates wide,
    /// anchored where the nested chain ends — at whatever capacity it is
    /// asked for, not at one blessed shape.
    #[test]
    fn layout_tiles_the_run() {
        for polys in [1, 3, 8] {
            let capacity = crate::framework_hooks::HookLayout {
                challenge: crate::framework_hooks::ChallengeLayout {
                    calls: 1,
                    width: 2,
                },
                poly_query: crate::framework_hooks::PolyQueryLayout { polys, claims: 1 },
            };
            let layout = layout::<EqAffine, R>(capacity);

            assert_eq!(layout.len(), polys, "one slot per polynomial");
            assert_eq!(
                layout.skip_gates(0),
                crate::internal::nested::chain_layout::<EqAffine, R>(capacity, capacity, capacity)
                    .final_skip_gates(),
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
