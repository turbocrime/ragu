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
//! occupy a distinct, statically-known region of the trace. The types are
//! macro-generated because the chain is expressed through the `Parent`
//! associated type, which cannot be computed from a const generic on stable
//! Rust.

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

/// Number of curve points in each claim-bridge stage: one host commitment.
const NUM: usize = 1;

/// Witness for a single claim slot's bridge stage: that claim's host-curve
/// commitment.
pub struct Witness<C: CurveAffine> {
    pub host: C,
}

/// Prover-internal output gadget for a claim-bridge stage.
///
/// Stage communication data, not part of the circuit's public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub host: Point<'dr, D, C>,
}

macro_rules! claim_bridge_stage {
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

claim_bridge_stage!(
    Stage0,
    super::eval::Stage<C, R>,
    "Bridge stage for poly-query claim slot 0."
);
claim_bridge_stage!(
    Stage1,
    Stage0<C, R>,
    "Bridge stage for poly-query claim slot 1."
);
claim_bridge_stage!(
    Stage2,
    Stage1<C, R>,
    "Bridge stage for poly-query claim slot 2."
);
claim_bridge_stage!(
    Stage3,
    Stage2<C, R>,
    "Bridge stage for poly-query claim slot 3."
);

/// Compile-time guard: the number of macro-generated stages above must match
/// the number of claim slots. Bump both together.
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
