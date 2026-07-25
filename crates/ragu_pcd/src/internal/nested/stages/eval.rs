//! Eval stage for nested fuse operations.

use core::marker::PhantomData;

use ragu_arithmetic::CurveAffine;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Point,
    io::Write,
    vec::{CollectFixed, ConstLen, FixedVec},
};

use crate::NUM_POLY_QUERY_SLOTS;

/// Number of curve points in this stage.
const NUM: usize = 1 + NUM_POLY_QUERY_SLOTS + crate::NUM_CHALLENGE_SLOTS;

/// Witness data for this bridge stage.
pub struct Witness<C: CurveAffine> {
    pub native_eval: C,
    /// The current step's poly-query claim host commitments, in slot order.
    /// Stashed here — in a transcript-bound bridge stage — so the *parent's*
    /// copying circuit can check its preamble's stashed claim commitments
    /// against this proof's own record of them.
    pub claims: [C; NUM_POLY_QUERY_SLOTS],
    /// The current step's challenge-stage host commitments, in slot order,
    /// stashed for the same reason as the claims.
    pub challenge_stages: [C; crate::NUM_CHALLENGE_SLOTS],
}

/// Prover-internal output gadget for this bridge stage.
///
/// This is stage communication data, not part of the circuit's
/// public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub native_eval: Point<'dr, D, C>,
    /// The current step's poly-query claim host commitments, in slot order.
    #[ragu(gadget)]
    pub claims: FixedVec<Point<'dr, D, C>, ConstLen<NUM_POLY_QUERY_SLOTS>>,
    /// The current step's challenge-stage host commitments, in slot order.
    #[ragu(gadget)]
    pub challenge_stages: FixedVec<Point<'dr, D, C>, ConstLen<{ crate::NUM_CHALLENGE_SLOTS }>>,
}

#[derive(Default)]
pub struct Stage<C: CurveAffine, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R> {
    type Parent = super::f::Stage<C, R>;
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
            native_eval: Point::alloc(dr, witness.as_ref().map(|w| w.native_eval))?,
            claims: (0..NUM_POLY_QUERY_SLOTS)
                .map(|i| Point::alloc(dr, witness.as_ref().map(|w| w.claims[i])))
                .try_collect_fixed()?,
            challenge_stages: (0..crate::NUM_CHALLENGE_SLOTS)
                .map(|i| Point::alloc(dr, witness.as_ref().map(|w| w.challenge_stages[i])))
                .try_collect_fixed()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<EqAffine, R>::default());
    }
}
