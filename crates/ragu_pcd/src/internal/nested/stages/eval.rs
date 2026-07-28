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
use ragu_primitives::{
    Point,
    io::Write,
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

/// This stage's wire width for a step of shape `own` (the *current* step's
/// slots, not a child's); the value-level source of the typed
/// [`values()`](ragu_circuits::staging::Stage::values).
pub const fn num_values(own: crate::framework_hooks::HookLayout) -> usize {
    2 * (1 + own.poly_query.polys)
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
}

/// Prover-internal output gadget for this bridge stage.
///
/// This is stage communication data, not part of the circuit's
/// public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>, const POLYS: usize> {
    #[ragu(gadget)]
    pub native_eval: Point<'dr, D, C>,
    /// The current step's poly-query claim host commitments, in slot order.
    #[ragu(gadget)]
    pub claims: FixedVec<Point<'dr, D, C>, ConstLen<POLYS>>,
}

/// The current step's poly count sizes this stage's slots.
pub struct Stage<C: CurveAffine, R, const POLYS: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R, const POLYS: usize> Default for Stage<C, R, POLYS> {
    fn default() -> Self {
        Stage {
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank, const POLYS: usize> ragu_circuits::staging::Stage<C::Base, R>
    for Stage<C, R, POLYS>
{
    type Parent = super::f::Stage<C, R, POLYS>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _, C, POLYS>];

    fn values() -> usize {
        2 * (1 + POLYS)
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
            claims: ConstLen::<POLYS>::range()
                .map(|i| Point::alloc(dr, witness.as_ref().map(|w| w.claims[i])))
                .try_collect_fixed()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, capacity_with_polys, stage_wire_count};

    /// `num_values` predicts the wire count at every shape, not just one.
    #[test]
    fn num_values_matches_wire_count() {
        fn check<const POLYS: usize>() {
            assert_eq!(
                stage_wire_count(&Stage::<EqAffine, R, POLYS>::default()),
                num_values(capacity_with_polys(POLYS)),
                "polys={POLYS}"
            );
        }
        check::<0>();
        check::<1>();
        check::<4>();
        check::<8>();
    }
}
