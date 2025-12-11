use ff::Field;
use ragu_core::{
    Result,
    drivers::Driver,
    gadgets::{Gadget, GadgetKind, Kind},
};
use ragu_primitives::{
    Element,
    io::{Buffer, Write},
};

/// Compositional gadget that appends a suffix element to another gadget during
/// serialization.
#[derive(Gadget)]
pub struct Suffix<'dr, D: Driver<'dr>, G: GadgetKind<D::F>> {
    #[ragu(gadget)]
    inner: G::Rebind<'dr, D>,
    #[ragu(gadget)]
    suffix: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>, G: GadgetKind<D::F>> Suffix<'dr, D, G> {
    pub fn new(inner: G::Rebind<'dr, D>, suffix: Element<'dr, D>) -> Self {
        Suffix { inner, suffix }
    }
}

impl<F: Field, K: GadgetKind<F> + Write<F>> Write<F> for Kind![F; @Suffix<'_, _, K>] {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Self::Rebind<'dr, D>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        K::write_gadget(&this.inner, dr, buf)?;
        buf.write(dr, &this.suffix)
    }
}
