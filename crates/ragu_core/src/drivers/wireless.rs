use core::marker::PhantomData;

use super::{Coeff, Driver, DriverTypes, Field, FromDriver, MaybeKind, Result};

/// A driver that does not track wires or wire assignments, and does not enforce
/// constraints.
pub struct Wireless<M: MaybeKind, F: Field> {
    _marker: PhantomData<(M, F)>,
}

impl<M: MaybeKind, F: Field> Driver<'_> for Wireless<M, F> {
    type F = F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        Ok(())
    }

    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        Ok(((), (), ()))
    }

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {}

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        Ok(())
    }
}

impl<M: MaybeKind, F: Field> DriverTypes for Wireless<M, F> {
    type ImplField = F;
    type ImplWire = ();
    type MaybeKind = M;
    type LCadd = ();
    type LCenforce = ();
}

impl<M: MaybeKind, F: Field> Default for Wireless<M, F> {
    /// Creates a new instance of `Wireless`.
    fn default() -> Self {
        Wireless {
            _marker: PhantomData,
        }
    }
}

impl<'dr, 'new_dr, D: Driver<'dr>> FromDriver<'dr, 'new_dr, D> for Wireless<D::MaybeKind, D::F> {
    type NewDriver = Self;

    fn convert_wire(&mut self, _: &D::Wire) -> <Self::NewDriver as Driver<'new_dr>>::Wire {}
}
