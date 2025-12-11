//! A stub circuit used only for verification to compute unified k(Y).

use arithmetic::Cycle;
use ragu_circuits::Circuit;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
};

use crate::internal_circuits::unified::{self, OutputBuilder};

/// A stub circuit for computing unified k(Y) in verification.
/// This mimics the instance method of C and V circuits without
/// instantiating the full circuits.
pub(crate) struct StubUnified<C> {
    _marker: core::marker::PhantomData<C>,
}

impl<C> StubUnified<C> {
    pub fn new() -> Self {
        StubUnified {
            _marker: core::marker::PhantomData,
        }
    }
}

impl<C: Cycle> Circuit<C::CircuitField> for StubUnified<C> {
    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = ();
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>> {
        OutputBuilder::new().finish(dr, &instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _dr: &mut D,
        _witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        unreachable!("StubUnified::witness should never be called")
    }
}
