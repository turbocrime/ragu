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

/// The claim-slot count for the *typed* [`Run`] only.
///
/// A `Stage`'s associated `values()` takes no arguments, so the run has to
/// name some length there. The real one is the application's poly capacity,
/// which every construction takes as a value through [`layout`]; this is only
/// what the typed self-consistency check measures against.
pub struct Slots;

impl Len for Slots {
    fn len() -> usize {
        crate::framework_hooks::HookLayout::typed_placeholder()
            .poly_query
            .polys
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
    use ragu_circuits::staging::{Stage, StageExt};
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    /// The field the nested stages are defined over.
    type F = <EqAffine as CurveAffine>::Base;

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Slot::<EqAffine, R>::default());
        assert_stage_values(&Run::<EqAffine, R>::default());
    }

    /// The layout tiles the run exactly at the placeholder shape: one slot per
    /// claim, starting where the run starts and ending where it ends.
    ///
    /// Only the placeholder shape can be checked against the typed run, since
    /// that is the shape the typed side names. Real geometry is checked where
    /// it is used, by `configure_induced_sized` against the chain layout.
    #[test]
    fn layout_tiles_the_run() {
        let placeholder = crate::framework_hooks::HookLayout::typed_placeholder();
        let layout = layout::<EqAffine, R>(placeholder);

        assert_eq!(layout.len(), placeholder.poly_query.polys);
        assert_eq!(
            layout.skip_gates(0),
            <Run<EqAffine, R> as Stage<F, R>>::skip_gates(),
            "the first slot does not start where the run does"
        );
        assert_eq!(
            layout.final_skip_gates(),
            <Run<EqAffine, R> as Stage<F, R>>::skip_gates()
                + <Run<EqAffine, R> as StageExt<F, R>>::num_gates(),
            "the slots do not fill the run"
        );
    }
}
