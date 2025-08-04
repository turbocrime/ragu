//! Traits for serializing gadgets into a sequence of [`Element`]s.

use ragu_core::{Result, drivers::Driver, gadgets::Gadget};

use crate::Element;

/// Represents a gadget that can be serialized into a sequence of [`Element`]s
/// that are written to a [`Buffer`].
pub trait GadgetSerialize<'dr, D: Driver<'dr>>: Gadget<'dr, D> {
    /// Serialize this gadget into wires that are written the provided buffer,
    /// using the driver to synthesize the elements if needed.
    fn serialize<B: Buffer<'dr, D>>(&self, dr: &mut D, buf: &mut B) -> Result<()>;
}

/// Represents a destination for values with some context `D`, such as a
/// [`Driver`].
pub trait Buffer<'dr, D: Driver<'dr>> {
    /// Push an `Element` into this buffer using the provided driver `D`.
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()>;
}
