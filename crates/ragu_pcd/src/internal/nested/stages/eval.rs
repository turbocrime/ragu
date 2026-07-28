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

use crate::slot_vec::SlotVec;

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
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub native_eval: Point<'dr, D, C>,
    /// The current step's poly-query claim host commitments, in slot order.
    #[ragu(gadget)]
    pub claims: SlotVec<Point<'dr, D, C>>,
}

pub struct Stage<C: CurveAffine, R> {
    /// The current step's own shape: its poly count sizes this stage's slots.
    own: crate::framework_hooks::HookLayout,
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R> Stage<C, R> {
    /// A stage instance for a step of the given shape.
    pub fn with_shape(own: crate::framework_hooks::HookLayout) -> Self {
        Stage {
            own,
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R> {
    type Parent = super::f::Stage<C, R>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _, C>];

    fn values() -> usize {
        crate::internal::shape_dependent_stage()
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
            claims: (0..self.own.poly_query.polys)
                .map(|i| Point::alloc(dr, witness.as_ref().map(|w| w.claims[i])))
                .collect::<Result<_>>()?,
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
        for polys in [0, 1, 4, 8] {
            let capacity = capacity_with_polys(polys);
            assert_eq!(
                stage_wire_count(&Stage::<EqAffine, R>::with_shape(capacity)),
                num_values(capacity),
                "polys={polys}"
            );
        }
    }
}
