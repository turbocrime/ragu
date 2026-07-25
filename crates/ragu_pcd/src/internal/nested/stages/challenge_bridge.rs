//! Per-challenge bridge stages: one committed stage per challenge slot.
//!
//! A challenge slot's stage lives in the *application* circuit, so its
//! commitment is a host-curve point — coordinates in `ScalarField`, which a
//! native circuit cannot witness. This bridges it: the stage here carries that
//! host commitment as its wires, and committing this stage yields a
//! nested-curve point whose coordinates *are* `CircuitField`, so the native
//! side can witness it and hash it into the challenge.
//!
//! That is the same construction as [`super::claim_bridge`], and for the same
//! reason: every value that has to cross the curve boundary does so as a stage
//! commitment (see [`super::f`]). Both families share
//! [`host_bridge::Stage`](super::host_bridge::Stage); only the chain differs.
//!
//! Each slot gets its own stage, chained after the claim bridges, so slot `i`'s
//! wires occupy a distinct, statically-known region of the trace.

/// Bridge stage for challenge slot 0.
pub type Stage0<C, R> = super::host_bridge::Stage<C, R, super::claim_bridge::Stage3<C, R>>;
/// Bridge stage for challenge slot 1.
pub type Stage1<C, R> = super::host_bridge::Stage<C, R, Stage0<C, R>>;

/// Compile-time guard: the number of aliases above must match the number of
/// challenge slots. Bump both together.
const _: () = assert!(crate::NUM_CHALLENGE_SLOTS == 2);

#[cfg(test)]
mod tests {
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage0::<EqAffine, R>::default());
        assert_stage_values(&Stage1::<EqAffine, R>::default());
    }
}
