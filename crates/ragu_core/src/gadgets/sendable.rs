use core::marker::PhantomData;

use crate::{drivers::Driver, gadgets::Gadget};

/// Wrapper for a concrete gadget that implements [`Send`] when parameterized by
/// a driver with `Send` wires.
pub struct Sendable<'dr, D, G>
where
    D: Driver<'dr>,
    G: Gadget<'dr, D>,
{
    gadget: G,
    _marker: PhantomData<(&'dr (), *mut D)>,
}

impl<'dr, D, G> Sendable<'dr, D, G>
where
    D: Driver<'dr>,
    G: Gadget<'dr, D>,
{
    /// Creates a new `Sendable` wrapper around the given gadget.
    pub fn new(gadget: G) -> Self
    where
        D::Wire: Send,
    {
        Sendable {
            gadget,
            _marker: PhantomData,
        }
    }

    /// Extracts the wrapped gadget.
    pub fn into_inner(self) -> G {
        self.gadget
    }
}

/// [`Sendable`]s are themselves [`Send`] for all concrete gadgets so long as
/// the driver has a [`Send`] wire type.
///
/// This follows because:
///
/// * The [`Gadget`] trait has an associated
///   [`GadgetKind`](crate::gadgets::GadgetKind) with a
///   [`Rebind`](crate::gadgets::GadgetKind::Rebind) type that is required by
///   [`Gadget`] to rebind the gadget to itself.
/// * The [`GadgetKind`](crate::gadgets::GadgetKind) trait is `unsafe` and the
///   implementor must ensure that all of the rebound gadget's contents are
///   either wires, gadgets, witness data, or other data that is required to be
///   [`Send`].
/// * Witnesses are always [`Send`] by the bound on
///   [`Maybe<T>`](crate::maybe::Maybe).
/// * Gadgets are [`Send`] by induction if they have a `Send` wire type.
unsafe impl<'dr, D: Driver<'dr, Wire: Send>, G: Gadget<'dr, D>> Send for Sendable<'dr, D, G> {}
