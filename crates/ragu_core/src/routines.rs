//! Functions that take [gadgets](crate::gadgets) as input and produce gadgets
//! as output.
//!
//! Routines are intended for portions of the circuit that are either invoked
//! multiple times (and so drivers can memoize their synthesis) or have
//! efficiently predictable outputs (and so drivers can parallelize their
//! synthesis).

use ff::Field;

use crate::{
    Result,
    drivers::{Driver, Wireless, Witness},
    gadgets::GadgetKind,
};

/// Sections of a circuit that take a [`Gadget`](crate::gadgets::Gadget) as
/// input and produce a [`Gadget`](crate::gadgets::Gadget) as output.
///
/// Routines provide a [`predict`](Routine::predict) method so that drivers can
/// optionally ask the routine implementor to predict the output gadget value by
/// returning a [`Prediction`]. If the gadget output cannot be efficiently
/// predicted then at least any auxillary data that may be useful for execution
/// can be returned.
///
/// The actual synthesis of a routine is performed in the
/// [`execute`](Routine::execute) method. Drivers can leverage predictions to
/// execute routines in parallel (for witness generation) or skip execution if
/// synthesis is memoized.
pub trait Routine<F: Field>: Clone + Send {
    /// The kind of a gadget that this routine expects as input
    type Input: GadgetKind<F>;

    /// The kind of a gadget that this routine expects as output
    type Output: GadgetKind<F>;

    /// The auxillary data that may be provided by the
    /// [`predict`](Routine::predict) method to be used during actual execution,
    /// to avoid redundant computations.
    type Aux<'dr>: Send + Clone;

    /// Execute the routine with a driver given the designated input, returning
    /// the designated output.
    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: <Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
        aux: Witness<D, Self::Aux<'dr>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>>;

    /// Routines can offer to predict their outputs given their inputs, which
    /// drivers can leverage to skip actual execution or perform it in a
    /// background thread. In any event, the prediction process produces some
    /// routine-specific auxiliary data that can be leveraged during actual
    /// execution to avoid duplicated effort.
    fn predict<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: &<Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
    ) -> Result<
        Prediction<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>, Witness<D, Self::Aux<'dr>>>,
    >;
}

/// Describes the result of a routine's [`predict`](Routine::predict) method.
///
/// `Known(T, A)` represents a known prediction of output `T` and `Unknown(A)`
/// represents an unpredictable result, in either case `A` represents auxiliary
/// data that may be useful for execution.
pub enum Prediction<T, A> {
    /// The routine has provided the resulting `T` value and some auxiliary
    /// information that may be useful for actual execution.
    Known(T, A),

    /// The routine cannot (efficiently) predict the result of execution, and
    /// the driver should simply execute it to obtain the result.
    Unknown(A),
}

/// Helper trait for routines.
pub trait RoutineExt<F: Field>: Routine<F> {
    /// Executes a routine for a driver, discarding the routine's prediction but
    /// forwarding its auxiliary data to the execution method. This is the
    /// default behavior of the [`Driver`] trait.
    fn predict_and_execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: <Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        let mut dummy = Wireless::<D::MaybeKind, F>::default();
        let dummy_input = Self::Input::map(&input, &mut dummy);
        match self.predict(&mut dummy, &dummy_input)? {
            Prediction::Known(_, aux) | Prediction::Unknown(aux) => self.execute(dr, input, aux),
        }
    }
}

impl<F: Field, R: Routine<F>> RoutineExt<F> for R {}
