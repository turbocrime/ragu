//! Strips away the witness data from a gadget while still preserving access to
//! it.

use ff::Field;
use ragu_core::{
    Result,
    drivers::{Coeff, Driver, DriverTypes, FromDriver},
    gadgets::{Gadget, GadgetKind},
    maybe::Empty,
};

use core::ops::Deref;

/// A driver that mimics another driver but strips away witness data.
pub struct DemotedDriver<'dr, D: Driver<'dr>> {
    _marker: core::marker::PhantomData<(&'dr (), D)>,
}

impl<'dr, D: Driver<'dr>> DemotedDriver<'dr, D> {
    // This is not public so that it is not constructible outside of this
    // module.
    fn new() -> Self {
        DemotedDriver {
            _marker: core::marker::PhantomData,
        }
    }
}

impl<'dr, D: Driver<'dr>> DriverTypes for DemotedDriver<'dr, D> {
    type MaybeKind = Empty;
    type LCadd = ();
    type LCenforce = ();
    type ImplField = D::F;
    type ImplWire = D::Wire;
}

impl<'dr, D: Driver<'dr>> Driver<'dr> for DemotedDriver<'dr, D> {
    const ONE: D::Wire = D::ONE;
    type F = D::F;
    type Wire = D::Wire;

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        unreachable!("DemotedDriver cannot be constructed")
    }

    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<Self::F>, Coeff<Self::F>, Coeff<Self::F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        unreachable!("DemotedDriver cannot be constructed")
    }

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        unreachable!("DemotedDriver cannot be constructed")
    }

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        unreachable!("DemotedDriver cannot be constructed")
    }
}

impl<'dr, D: Driver<'dr>> FromDriver<'dr, 'dr, D> for DemotedDriver<'dr, D> {
    type NewDriver = Self;

    fn convert_wire(&mut self, wire: &D::Wire) -> <Self::NewDriver as Driver<'dr>>::Wire {
        wire.clone()
    }
}

/// Simple redirect of wire conversion to the underlying driver.
struct Demoter<'a, F> {
    driver: &'a mut F,
}

impl<'dr, 'new_dr, D: Driver<'dr>, F: FromDriver<'dr, 'new_dr, D>>
    FromDriver<'dr, 'new_dr, DemotedDriver<'dr, D>> for Demoter<'_, F>
{
    type NewDriver = DemotedDriver<'new_dr, F::NewDriver>;

    fn convert_wire(&mut self, wire: &D::Wire) -> <Self::NewDriver as Driver<'new_dr>>::Wire {
        self.driver.convert_wire(wire)
    }
}

/// A gadget that strips witness data from another gadget.
pub struct Demoted<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> {
    gadget: <G::Kind as GadgetKind<D::F>>::Rebind<'dr, DemotedDriver<'dr, D>>,
}

impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Deref for Demoted<'dr, D, G> {
    type Target = <G::Kind as GadgetKind<D::F>>::Rebind<'dr, DemotedDriver<'dr, D>>;

    fn deref(&self) -> &Self::Target {
        &self.gadget
    }
}

impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Demoted<'dr, D, G> {
    /// Strips a gadget of its witness data and returns a demoted version of it.
    pub fn new(gadget: &G) -> Self {
        Demoted {
            gadget: <G::Kind as GadgetKind<D::F>>::map(gadget, &mut DemotedDriver::new()),
        }
    }
}

impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Clone for Demoted<'dr, D, G> {
    fn clone(&self) -> Self {
        Demoted {
            gadget: self.gadget.clone(),
        }
    }
}

/// A [`GadgetKind`] for the [`Demoted`] gadget.
#[doc(hidden)]
pub struct DemotedKind<F: Field, G: GadgetKind<F>> {
    _marker: core::marker::PhantomData<(G, F)>,
}

impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Gadget<'dr, D> for Demoted<'dr, D, G> {
    type Kind = DemotedKind<D::F, G::Kind>;
}

unsafe impl<F: Field, G: GadgetKind<F>> GadgetKind<F> for DemotedKind<F, G> {
    type Rebind<'dr, D: Driver<'dr, F = F>> = Demoted<'dr, D, G::Rebind<'dr, D>>;

    fn map<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
        this: &Self::Rebind<'dr, D>,
        ndr: &mut ND,
    ) -> Self::Rebind<'new_dr, ND::NewDriver> {
        Demoted {
            gadget: G::map(&this.gadget, &mut Demoter { driver: ndr }),
        }
    }
}
