//! Eval stage for nested fuse operations.

use alloc::vec::Vec;
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

use crate::{NUM_CHALLENGE_SLOTS, NUM_POLY_SLOTS, slot_vec::SlotVec};

/// This stage's wire width for a step of shape `own` (the *current* step's
/// slots, not a child's); the value-level source of the typed
/// [`values()`](ragu_circuits::staging::Stage::values).
pub const fn num_values(own: crate::framework_hooks::HookLayout) -> usize {
    2 * (1 + own.poly_query.polys + own.challenge.calls)
}

/// Witness data for this bridge stage.
pub struct Witness<C: CurveAffine> {
    pub native_eval: C,
    /// The current step's poly-query claim host commitments, in slot order.
    /// Stashed here — in a transcript-bound bridge stage — so the *parent's*
    /// copying circuit can check its preamble's stashed claim commitments
    /// against this proof's own record of them.
    ///
    /// Must contain exactly the stage's poly-slot count; the stage body
    /// indexes it up to that count.
    pub claims: Vec<C>,
    /// The current step's challenge-stage host commitments, in slot order,
    /// stashed for the same reason as the claims. Length disciplined like
    /// `claims`, at the stage's challenge-slot count.
    pub challenge_stages: Vec<C>,
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
    pub claims: SlotVec<Point<'dr, D, C>>,
    /// The current step's challenge-stage host commitments, in slot order.
    #[ragu(gadget)]
    pub challenge_stages: SlotVec<Point<'dr, D, C>>,
}

pub struct Stage<C: CurveAffine, R> {
    /// Number of poly-query claim slots this stage instance carries.
    num_polys: usize,
    /// Number of challenge-stage slots this stage instance carries.
    num_challenges: usize,
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R> Default for Stage<C, R> {
    fn default() -> Self {
        Stage {
            num_polys: NUM_POLY_SLOTS,
            num_challenges: NUM_CHALLENGE_SLOTS,
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R> {
    type Parent = super::f::Stage<C, R>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _, C>];

    fn values() -> usize {
        num_values(crate::framework_hooks::HookLayout::padded())
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
            claims: (0..self.num_polys)
                .map(|i| Point::alloc(dr, witness.as_ref().map(|w| w.claims[i])))
                .collect::<Result<_>>()?,
            challenge_stages: (0..self.num_challenges)
                .map(|i| Point::alloc(dr, witness.as_ref().map(|w| w.challenge_stages[i])))
                .collect::<Result<_>>()?,
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
