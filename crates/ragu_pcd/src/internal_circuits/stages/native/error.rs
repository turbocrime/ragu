//! Error stage for merge operations.

use arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Point,
    vec::{CollectFixed, FixedVec, Len},
};

use core::marker::PhantomData;

pub use crate::internal_circuits::InternalCircuitIndex::ErrorStage as STAGING_ID;

use crate::components::fold_revdot::ErrorTermsLen;

/// Witness data for the error stage.
pub struct Witness<C: Cycle, const NUM_REVDOT_CLAIMS: usize> {
    /// The z challenge derived from hashing w and nested_s_prime_commitment.
    pub z: C::CircuitField,
    /// The nested s'' commitment point.
    pub nested_s_doubleprime_commitment: C::NestedCurve,
    /// Error term elements.
    pub error_terms: FixedVec<C::CircuitField, ErrorTermsLen<NUM_REVDOT_CLAIMS>>,
}

/// Output gadget for the error stage.
#[derive(Gadget)]
pub struct Output<'dr, D: Driver<'dr>, C: Cycle, const NUM_REVDOT_CLAIMS: usize> {
    /// The witnessed z challenge element.
    #[ragu(gadget)]
    pub z: Element<'dr, D>,
    /// The nested s'' commitment point.
    #[ragu(gadget)]
    pub nested_s_doubleprime_commitment: Point<'dr, D, C::NestedCurve>,
    /// Error term elements.
    #[ragu(gadget)]
    pub error_terms: FixedVec<Element<'dr, D>, ErrorTermsLen<NUM_REVDOT_CLAIMS>>,
}

/// The error stage of the merge witness.
#[derive(Default)]
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize, const NUM_REVDOT_CLAIMS: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, const NUM_REVDOT_CLAIMS: usize>
    staging::Stage<C::CircuitField, R> for Stage<C, R, HEADER_SIZE, NUM_REVDOT_CLAIMS>
{
    type Parent = super::preamble::Stage<C, R, HEADER_SIZE>;
    type Witness<'source> = &'source Witness<C, NUM_REVDOT_CLAIMS>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _, C, NUM_REVDOT_CLAIMS>];

    fn values() -> usize {
        // 1 for z + 2 for S'' + error terms
        1 + 2 + ErrorTermsLen::<NUM_REVDOT_CLAIMS>::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let z = Element::alloc(dr, witness.view().map(|w| w.z))?;
        let nested_s_doubleprime_commitment = Point::alloc(
            dr,
            witness.view().map(|w| w.nested_s_doubleprime_commitment),
        )?;
        let error_terms = ErrorTermsLen::<NUM_REVDOT_CLAIMS>::range()
            .map(|i| Element::alloc(dr, witness.view().map(|w| w.error_terms[i])))
            .try_collect_fixed()?;

        Ok(Output {
            z,
            nested_s_doubleprime_commitment,
            error_terms,
        })
    }
}
