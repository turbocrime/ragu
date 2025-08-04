//! Implementations of gadgets for foreign types.

use alloc::boxed::Box;
use core::marker::PhantomData;
use ff::Field;

use crate::{
    drivers::{Driver, FromDriver},
    gadgets::{Gadget, GadgetKind},
};

mod unit_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>> Gadget<'dr, D> for () {
        type Kind = ();
    }

    unsafe impl<F: Field> GadgetKind<F> for () {
        type Rebind<'dr, D: Driver<'dr, F = F>> = ();

        fn map<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
            _: &Self::Rebind<'dr, D>,
            _: &mut ND,
        ) -> Self::Rebind<'new_dr, ND::NewDriver> {
        }
    }
}

mod array_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>, const N: usize> Gadget<'dr, D> for [G; N] {
        type Kind = [PhantomData<G::Kind>; N];
    }

    unsafe impl<F: Field, G: GadgetKind<F>, const N: usize> GadgetKind<F> for [PhantomData<G>; N] {
        type Rebind<'dr, D: Driver<'dr, F = F>> = [G::Rebind<'dr, D>; N];

        fn map<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
            this: &Self::Rebind<'dr, D>,
            ndr: &mut ND,
        ) -> Self::Rebind<'new_dr, ND::NewDriver> {
            core::array::from_fn(|i| G::map(&this[i], ndr))
        }
    }
}

mod pair_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>, G1: Gadget<'dr, D>, G2: Gadget<'dr, D>> Gadget<'dr, D> for (G1, G2) {
        type Kind = (PhantomData<G1::Kind>, PhantomData<G2::Kind>);
    }

    unsafe impl<F: Field, G1: GadgetKind<F>, G2: GadgetKind<F>> GadgetKind<F>
        for (PhantomData<G1>, PhantomData<G2>)
    {
        type Rebind<'dr, D: Driver<'dr, F = F>> = (G1::Rebind<'dr, D>, G2::Rebind<'dr, D>);

        fn map<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
            this: &Self::Rebind<'dr, D>,
            ndr: &mut ND,
        ) -> Self::Rebind<'new_dr, ND::NewDriver> {
            (G1::map(&this.0, ndr), G2::map(&this.1, ndr))
        }
    }
}

mod box_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Gadget<'dr, D> for Box<G> {
        type Kind = PhantomData<Box<G::Kind>>;
    }

    unsafe impl<F: Field, G: GadgetKind<F>> GadgetKind<F> for PhantomData<Box<G>> {
        type Rebind<'dr, D: Driver<'dr, F = F>> = Box<G::Rebind<'dr, D>>;

        fn map<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
            this: &Self::Rebind<'dr, D>,
            ndr: &mut ND,
        ) -> Self::Rebind<'new_dr, ND::NewDriver> {
            Box::new(G::map(this, ndr))
        }
    }
}
