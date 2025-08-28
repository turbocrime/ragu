use core::marker::PhantomData;
use ff::Field;

use crate::{
    Result,
    drivers::{Coeff, Driver, DriverTypes, FromDriver},
    gadgets::GadgetKind,
    maybe::MaybeKind,
    routines::{Prediction, Routine},
};

/// A driver used to execute circuit synthesis code and obtain the result of a
/// computation without enforcing constraints or collecting a witness. Useful
/// for obtaining the result of a computation that is later executed with
/// another driver.
pub struct Emulator<M: MaybeKind, F: Field> {
    _marker: PhantomData<(M, F)>,
}

impl<M: MaybeKind, F: Field> Default for Emulator<M, F> {
    fn default() -> Self {
        Emulator::new()
    }
}

impl<M: MaybeKind, F: Field> Emulator<M, F> {
    /// Creates a new `Emulator` driver.
    pub fn new() -> Self {
        Emulator {
            _marker: PhantomData,
        }
    }

    /// Executes a closure with this driver, returning its output.
    pub fn just<R, W: Send>(&mut self, f: impl FnOnce(&mut Self) -> Result<R>) -> Result<R> {
        f(self)
    }

    /// Executes a closure with this driver, passing a witness value into the
    /// closure and returning its output.
    pub fn with<R, W: Send>(
        &mut self,
        witness: W,
        f: impl FnOnce(&mut Self, M::Rebind<W>) -> Result<R>,
    ) -> Result<R> {
        f(self, M::maybe_just(|| witness))
    }
}

impl<M: MaybeKind, F: Field> DriverTypes for Emulator<M, F> {
    type ImplField = F;
    type ImplWire = ();
    type MaybeKind = M;
    type LCadd = ();
    type LCenforce = ();
}

impl<'dr, M: MaybeKind, F: Field> Driver<'dr> for Emulator<M, F> {
    type F = F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        Ok(())
    }

    fn constant(&mut self, _: Coeff<Self::F>) -> Self::Wire {}

    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<Self::F>, Coeff<Self::F>, Coeff<Self::F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        Ok(((), (), ()))
    }

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {}

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        Ok(())
    }

    fn routine<R: Routine<Self::F> + 'dr>(
        &mut self,
        routine: R,
        input: <R::Input as GadgetKind<Self::F>>::Rebind<'dr, Self>,
    ) -> Result<<R::Output as GadgetKind<Self::F>>::Rebind<'dr, Self>> {
        // Emulator will short-circuit execution if the routine can predict its
        // output, as the emulator is not involved in enforcing any constraints.
        match routine.predict(self, &input)? {
            Prediction::Known(output, _) => Ok(output),
            Prediction::Unknown(aux) => routine.execute(self, input, aux),
        }
    }
}

impl<'dr, D: Driver<'dr>> FromDriver<'dr, '_, D> for Emulator<D::MaybeKind, D::F> {
    type NewDriver = Self;

    fn convert_wire(&mut self, _: &D::Wire) -> Result<()> {
        Ok(())
    }
}
