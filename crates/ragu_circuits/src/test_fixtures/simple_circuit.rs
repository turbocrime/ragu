//! A simple circuit for testing and benchmarks.
//!
//! Proves knowledge of a and b such that a^5 = b^2 and outputs c = a+b, d = a-b.

use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::Element;

use crate::Circuit;

/// A simple circuit that proves knowledge of a and b such that a^5 = b^2
/// and a + b = c and a - b = d where c and d are public inputs.
pub struct MySimpleCircuit;

impl<F: Field> Circuit<F> for MySimpleCircuit {
    type Instance<'instance> = (F, F); // Public inputs: c and d
    type Output = Kind![F; (Element<'_, _>, Element<'_, _>)];
    type Witness<'witness> = (F, F); // Witness: a and b
    type Aux<'witness> = ();

    fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'instance>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        let c = Element::alloc(dr, instance.view().map(|v| v.0))?;
        let d = Element::alloc(dr, instance.view().map(|v| v.1))?;

        Ok((c, d))
    }

    fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'witness>>,
    ) -> Result<(
        <Self::Output as GadgetKind<F>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'witness>>,
    )> {
        let a = Element::alloc(dr, witness.view().map(|w| w.0))?;
        let b = Element::alloc(dr, witness.view().map(|w| w.1))?;

        let a2 = a.square(dr)?;
        let a4 = a2.square(dr)?;
        let a5 = a4.mul(dr, &a)?;

        let b2 = b.square(dr)?;

        dr.enforce_zero(|lc| lc.add(a5.wire()).sub(b2.wire()))?;

        let c = a.add(dr, &b);
        let d = a.sub(dr, &b);

        Ok(((c, d), D::just(|| ())))
    }
}
