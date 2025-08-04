use ragu_core::{Result, drivers::Driver};

use alloc::boxed::Box;

use crate::serialize::{Buffer, GadgetSerialize};

impl<'dr, D: Driver<'dr>> GadgetSerialize<'dr, D> for () {
    fn serialize<B: Buffer<'dr, D>>(&self, _: &mut D, _: &mut B) -> Result<()> {
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>, G: GadgetSerialize<'dr, D>, const N: usize> GadgetSerialize<'dr, D>
    for [G; N]
{
    fn serialize<B: Buffer<'dr, D>>(&self, dr: &mut D, buf: &mut B) -> Result<()> {
        for item in self {
            G::serialize(item, dr, buf)?;
        }
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>, G1: GadgetSerialize<'dr, D>, G2: GadgetSerialize<'dr, D>>
    GadgetSerialize<'dr, D> for (G1, G2)
{
    fn serialize<B: Buffer<'dr, D>>(&self, dr: &mut D, buf: &mut B) -> Result<()> {
        G1::serialize(&self.0, dr, buf)?;
        G2::serialize(&self.1, dr, buf)?;
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>, G: GadgetSerialize<'dr, D>> GadgetSerialize<'dr, D> for Box<G> {
    fn serialize<B: Buffer<'dr, D>>(&self, dr: &mut D, buf: &mut B) -> Result<()> {
        G::serialize(self, dr, buf)
    }
}
