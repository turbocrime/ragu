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
//! commitment (see [`super::f`]).
//!
//! Each slot gets its own stage, chained after the claim bridges, so slot `i`'s
//! wires occupy a distinct, statically-known region of the trace.

use core::marker::PhantomData;

use ragu_arithmetic::CurveAffine;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Point, io::Write};

/// Number of curve points in each challenge-bridge stage: one host commitment.
const NUM: usize = 1;

/// Witness for a single challenge slot's bridge stage: that slot's host-curve
/// stage commitment.
pub struct Witness<C: CurveAffine> {
    pub host: C,
}

/// Prover-internal output gadget for a challenge-bridge stage.
///
/// Stage communication data, not part of the circuit's public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub host: Point<'dr, D, C>,
}

macro_rules! challenge_bridge_stage {
    ($name:ident, $parent:ty, $doc:expr) => {
        #[doc = $doc]
        #[derive(Default)]
        pub struct $name<C: CurveAffine, R> {
            _marker: PhantomData<(C, R)>,
        }

        impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for $name<C, R> {
            type Parent = $parent;
            type Witness<'source> = &'source Witness<C>;
            type OutputKind = Kind![C::Base; Output<'_, _, C>];

            fn values() -> usize {
                NUM * 2
            }

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<Bound<'dr, D, Self::OutputKind>>
            where
                Self: 'dr,
            {
                Ok(Output {
                    host: Point::alloc(dr, witness.as_ref().map(|w| w.host))?,
                })
            }
        }
    };
}

challenge_bridge_stage!(
    Stage0,
    super::claim_bridge::Stage3<C, R>,
    "Bridge stage for challenge slot 0."
);
challenge_bridge_stage!(
    Stage1,
    Stage0<C, R>,
    "Bridge stage for challenge slot 1."
);

/// Compile-time guard: the number of macro-generated stages above must match
/// the number of challenge slots. Bump both together.
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
