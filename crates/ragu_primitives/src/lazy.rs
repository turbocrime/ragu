use ragu_core::{
    Result,
    drivers::Driver,
    gadgets::{Gadget, GadgetKind},
    routines::Routine,
};

/// Represents a routine that is lazily evaluated.
///
/// Internally, this holds a gadget that is used as input for a routine. This
/// can only be used for routines that implement the [`Default`] trait.
#[derive(Gadget)]
pub struct Lazy<'dr, D: Driver<'dr>, R: Routine<D::F> + Default + 'static> {
    #[ragu(gadget)]
    gadget: <R::Input as GadgetKind<D::F>>::Rebind<'dr, D>,
}

impl<'dr, D: Driver<'dr>, R: Routine<D::F> + Default + 'static> Lazy<'dr, D, R> {
    /// Create a new lazily-evaluated routine.
    pub fn new(gadget: <R::Input as GadgetKind<D::F>>::Rebind<'dr, D>) -> Self {
        Lazy { gadget }
    }

    /// Execute the routine and return the result.
    pub fn execute(self, dr: &mut D) -> Result<<R::Output as GadgetKind<D::F>>::Rebind<'dr, D>> {
        dr.routine(R::default(), self.gadget)
    }
}
