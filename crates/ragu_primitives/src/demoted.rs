//! Strips away the witness data from a gadget while still preserving access to
//! it.
//!
//! ## Demotion
//!
//! All gadgets can be demoted using
//! [`GadgetExt::demote`](crate::GadgetExt::demote), producing a [`Demoted`]
//! version of the original gadget that has its witness data stripped away. As
//! an example, you might have a gadget that contains $64$ boolean-constrained
//! values:
//!
//! ```rust
//! # use ragu_primitives::{Boolean, GadgetExt, demoted::Demoted};
//! # use ragu_core::{Result, drivers::{Driver, Witness}, gadgets::Gadget};
//! #[derive(Gadget)]
//! struct U64<'dr, D: Driver<'dr>> {
//!     #[ragu(gadget)]
//!     // This is the output type of `[Boolean<'dr, D>; 64]::demote()`
//!     bits: Demoted<'dr, D, [Boolean<'dr, D>; 64]>,
//!     #[ragu(witness)]
//!     value: Witness<D, u64>,
//! }
//! ```
//!
// This example gadget maintains _access_ to the enclosed
// [`Boolean`](crate::Boolean) values, but each individual boolean does not
// need to store a separate `bool` value in memory. The `U64` gadget becomes
// responsible for maintaining the witness information (in this case, a `u64`
// value) that represents the value of the encapsulated booleans. This improves
// synthesis performance and reduces memory usage in some contexts without
// requiring gadgets to expose visibility into their internal state or
// sacrificing their ability to uphold invariants in their public interface.
//
// Demoted gadgets can still partake in synthesis. As an example, you could
// create a method for computing the logical AND of two `U64` values:
//
// ```rust
// # use ragu_primitives::{Boolean, GadgetExt, demoted::Demoted};
// # use ragu_core::{Result, drivers::{Driver, Witness}, gadgets::Gadget, maybe::Maybe};
// # #[derive(Gadget)]
// # struct U64<'dr, D: Driver<'dr>> {
// #    #[ragu(gadget)]
// #    // This is the output type of `[Boolean<'dr, D>; 64]::demote()`
// #    bits: Demoted<'dr, D, [Boolean<'dr, D>; 64]>,
// #    #[ragu(witness)]
// #    value: Witness<D, u64>,
// # }
// impl<'dr, D: Driver<'dr>> U64<'dr, D> {
//     pub fn and(&self, dr: &mut D, other: &Self) -> Result<Self> {
//         let mut bits = self.bits.clone();
//         for (a, b) in bits.iter_mut().zip(other.bits.iter()) {
//             *a = a.and(dr, b)?;
//         }
//
//         Ok(U64 {
//            bits,
//            value: self.value.and_then(|v| other.value.map(|o| v & o)),
//         })
//     }
// }
// ```
//!
//! ## Promotion
//!
//! If necessary, gadgets can be recovered from their demoted state. Gadgets
//! must opt into supporting this by implementing the [`Promotion`] trait. Users
//! can then promote demoted gadgets using the [`Demoted::promote`] method.

use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverTypes, FromDriver, Witness},
    gadgets::{Gadget, GadgetKind},
    maybe::Empty,
};

use core::ops::Deref;

/// Trait for gadgets that support promotion from a [`Demoted`] state.
///
/// Demoted gadgets can be promoted back to their original form using
/// [`Demoted::promote`] as long as the gadget implements this trait.
pub trait Promotion<F: Field>: GadgetKind<F> {
    /// The type of witness data needed to promote a demoted gadget.
    type Value: Send;

    /// Promote a demoted gadget with new witness data.
    fn promote<'dr, D: Driver<'dr, F = F>>(
        demoted: &Demoted<'dr, D, Self::Rebind<'dr, D>>,
        witness: Witness<D, Self::Value>,
    ) -> Self::Rebind<'dr, D>;
}

/// A driver that mimics another driver but strips away witness data.
#[doc(hidden)]
pub struct DemotedDriver<'dr, D: Driver<'dr>> {
    _marker: core::marker::PhantomData<(&'dr (), D)>,
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

    fn convert_wire(&mut self, wire: &D::Wire) -> Result<<Self::NewDriver as Driver<'dr>>::Wire> {
        Ok(wire.clone())
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

    fn convert_wire(
        &mut self,
        wire: &D::Wire,
    ) -> Result<<Self::NewDriver as Driver<'new_dr>>::Wire> {
        self.driver.convert_wire(wire)
    }
}

/// A gadget that strips witness data from another gadget.
///
/// All gadgets can be demoted using
/// [`GadgetExt::demote`](crate::GadgetExt::demote). The resulting gadget has
/// all of its witness data stripped away, but access to the gadget's interface
/// is maintained.
///
/// The original gadget can be recovered by [promotion](Promotion).
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
    pub fn new(gadget: &G) -> Result<Self> {
        Ok(Demoted {
            gadget: <G::Kind as GadgetKind<D::F>>::map_gadget(
                gadget,
                &mut DemotedDriver {
                    _marker: core::marker::PhantomData,
                },
            )?,
        })
    }

    /// Promote this demoted gadget with new witness data.
    pub fn promote(&self, witness: Witness<D, <G::Kind as Promotion<D::F>>::Value>) -> G
    where
        G::Kind: Promotion<D::F>,
    {
        <G::Kind as Promotion<D::F>>::promote(self, witness)
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

    fn map_gadget<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
        this: &Self::Rebind<'dr, D>,
        ndr: &mut ND,
    ) -> Result<Self::Rebind<'new_dr, ND::NewDriver>> {
        Ok(Demoted {
            gadget: G::map_gadget(&this.gadget, &mut Demoter { driver: ndr })?,
        })
    }

    fn enforce_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        dr: &mut D1,
        a: &Self::Rebind<'dr, D2>,
        b: &Self::Rebind<'dr, D2>,
    ) -> Result<()> {
        G::enforce_equal_gadget(dr, &a.gadget, &b.gadget)
    }
}
