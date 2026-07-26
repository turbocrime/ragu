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
//! [`host_bridge::Stage`] for the per-slot witness
//! body and [`host_bridge::Run`] for the span.
//!
//! ## Why this is a run too
//!
//! The challenge count is fixed by the framework, not by the application, so
//! this family *could* stay a chain of aliases. It is a run anyway, for two
//! reasons.
//!
//! It chains after [`claim_bridge::Run`](super::claim_bridge::Run), whose
//! length is an application parameter — so an alias chain here would carry that
//! parameter in its type, spreading the count into every name that mentions a
//! challenge bridge. As a run it takes the claim run's *gate span* instead, and
//! the parameter stops at the boundary.
//!
//! And with both families runs, every bridge position is described by an
//! [`InducedStages`] value. Geometry that is a value can travel to the places a
//! type cannot reach — notably the in-step path, which builds a bridge rx
//! without being generic over the counts.
//!
//! [`InducedStages`]: ragu_circuits::staging::InducedStages

use ragu_arithmetic::CurveAffine;
use ragu_circuits::{polynomials::Rank, staging::InducedStages};
use ragu_primitives::vec::ConstLen;

use super::host_bridge;
use crate::NUM_CHALLENGE_SLOTS;

/// The challenge-bridge family: every slot, as one stage chained after the
/// claim-bridge run.
pub type Run<C, R> =
    host_bridge::Run<C, R, super::claim_bridge::Run<C, R>, ConstLen<NUM_CHALLENGE_SLOTS>>;

/// The witness body for a single challenge slot; see
/// [`claim_bridge::Slot`](super::claim_bridge::Slot).
pub type Slot<C, R> = host_bridge::Stage<C, R, ()>;

/// The layout subdividing [`Run`] into one slot per challenge.
pub fn layout<C: CurveAffine, R: Rank>() -> InducedStages {
    Run::<C, R>::layout()
}

#[cfg(test)]
mod tests {
    use ragu_circuits::staging::{Stage, StageExt};
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    type F = <EqAffine as CurveAffine>::Base;

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Slot::<EqAffine, R>::default());
        assert_stage_values(&Run::<EqAffine, R>::default());
    }

    /// The layout tiles the run exactly, as [`super::super::claim_bridge`]'s
    /// does — and the run starts where the claim run ends, which is what makes
    /// the two families adjacent rather than overlapping.
    #[test]
    fn layout_tiles_the_run() {
        let layout = layout::<EqAffine, R>();
        let claims = super::super::claim_bridge::layout::<EqAffine, R>();

        assert_eq!(layout.len(), NUM_CHALLENGE_SLOTS);
        assert_eq!(
            layout.anchor(),
            claims.final_skip_gates(),
            "the challenge run does not begin where the claim run ends"
        );
        assert_eq!(
            layout.final_skip_gates(),
            <Run<EqAffine, R> as Stage<F, R>>::skip_gates()
                + <Run<EqAffine, R> as StageExt<F, R>>::num_gates(),
            "the slots do not fill the run"
        );
    }
}
