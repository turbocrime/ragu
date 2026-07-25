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
//! The stages chain after [`super::eval`] in slot order, so slot `i`'s wires
//! occupy a distinct, statically-known region of the trace. The stage itself is
//! [`host_bridge::Stage`](super::host_bridge::Stage), shared with
//! [`super::challenge_bridge`]; only the chain differs.

/// Bridge stage for poly-query claim slot 0.
pub type Stage0<C, R> = super::host_bridge::Stage<C, R, super::eval::Stage<C, R>>;
/// Bridge stage for poly-query claim slot 1.
pub type Stage1<C, R> = super::host_bridge::Stage<C, R, Stage0<C, R>>;
/// Bridge stage for poly-query claim slot 2.
pub type Stage2<C, R> = super::host_bridge::Stage<C, R, Stage1<C, R>>;
/// Bridge stage for poly-query claim slot 3.
pub type Stage3<C, R> = super::host_bridge::Stage<C, R, Stage2<C, R>>;

/// Compile-time guard: the number of aliases above must match the number of
/// claim slots. Bump both together.
const _: () = assert!(crate::NUM_POLY_QUERY_SLOTS == 4);

#[cfg(test)]
mod tests {
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage0::<EqAffine, R>::default());
        assert_stage_values(&Stage1::<EqAffine, R>::default());
        assert_stage_values(&Stage2::<EqAffine, R>::default());
        assert_stage_values(&Stage3::<EqAffine, R>::default());
    }
}
