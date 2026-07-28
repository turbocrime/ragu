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

/// The number of poly-query claim slots, as a type.
///
/// [`Len`] is how the framework carries a length that is known at compile time
/// but is not a literal — the same escape hatch `FixedVec` uses. Making the
/// count an application parameter means changing what this returns, not
/// rewriting the stage hierarchy.
pub struct Slots;

impl Len for Slots {
    fn len() -> usize {
        crate::NUM_POLY_SLOTS
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
pub fn layout<C: CurveAffine, R: Rank>() -> InducedStages {
    Run::<C, R>::layout()
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

    /// The layout tiles the run exactly: one slot per claim, starting where the
    /// run starts and ending where it ends.
    ///
    /// `configure_induced` enforces this at reservation time too, but pinning
    /// it here says which of the two descriptions moved when it breaks.
    #[test]
    fn layout_tiles_the_run() {
        let layout = layout::<EqAffine, R>();

        assert_eq!(layout.len(), crate::NUM_POLY_SLOTS);
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
