//! Circuit for verifying the first layer of the revdot reductions.
//!
//! This circuit verifies that the collapsed values in error_n match the result
//! of folding the error_m terms with the k(y) values (which are computed and
//! verified in hashes_1).
//!
//! This circuit is built using the preamble, error_m (for layer 1 error terms),
//! and error_n (for layer 2 error terms, collapsed values, and k(y) values)
//! native stages.

use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind},
    maybe::Maybe,
};
use ragu_primitives::{Element, vec::FixedVec};

use core::{iter::once, marker::PhantomData};

use super::{
    stages::native::{
        error_m as native_error_m, error_n as native_error_n, preamble as native_preamble,
    },
    unified::{self, OutputBuilder},
};
use crate::components::{
    claim_builder::{KySource, ky_values},
    fold_revdot,
};

pub(crate) use crate::circuits::InternalCircuitIndex::PartialCollapseCircuit as CIRCUIT_ID;

/// Circuit that verifies layer 1 revdot folding.
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    Circuit<C, R, HEADER_SIZE, FP>
{
    /// Create a new partial collapse circuit.
    pub fn new() -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            _marker: PhantomData,
        })
    }
}

/// Witness for the partial collapse circuit.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    /// Witness for the preamble stage (contains child unified instances with c values).
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    /// The unified instance containing challenges.
    pub unified_instance: &'a unified::Instance<C>,
    /// Witness for the error_n stage (layer 2 error terms + collapsed values).
    pub error_n_witness: &'a native_error_n::Witness<C, FP>,
    /// Witness for the error_m stage (layer 1 error terms).
    pub error_m_witness: &'a native_error_m::Witness<C, FP>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    StagedCircuit<C::CircuitField, R> for Circuit<C, R, HEADER_SIZE, FP>
{
    type Final = native_error_m::Stage<C, R, HEADER_SIZE, FP>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE, FP>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (error_n, builder) =
            builder.add_stage::<native_error_n::Stage<C, R, HEADER_SIZE, FP>>()?;
        let (error_m, builder) =
            builder.add_stage::<native_error_m::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();
        let preamble = preamble.unenforced(dr, witness.view().map(|w| w.preamble_witness))?;

        // TODO: these are unenforced for now, because error_n/error_m stages
        // aren't supposed to contain anything (yet) besides Elements, which
        // require no enforcement logic. Re-evaluate this in the future.
        let error_n = error_n.unenforced(dr, witness.view().map(|w| w.error_n_witness))?;
        let error_m = error_m.unenforced(dr, witness.view().map(|w| w.error_m_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Get mu, nu from unified instance
        let mu = unified_output.mu.get(dr, unified_instance)?;
        let nu = unified_output.nu.get(dr, unified_instance)?;
        let fold_products = fold_revdot::FoldProducts::new(dr, &mu, &nu)?;

        // Read k(y) values from error_n stage, plus child c values from
        // preamble. Ordering must match claim_builder.
        let ky = TwoProofKySource::new::<C, HEADER_SIZE, FP>(dr, &preamble, &error_n);
        let mut ky = ky_values(&ky);

        for (i, error_terms) in error_m.error_terms.iter().enumerate() {
            let ky = FixedVec::from_fn(|_| ky.next().unwrap());

            fold_products
                .fold_products_m::<FP>(dr, error_terms, &ky)?
                .enforce_equal(dr, &error_n.collapsed[i])?;
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}

/// Source for k(y) values for two-proof circuits.
struct TwoProofKySource<'dr, D: Driver<'dr>> {
    left_raw_c: Element<'dr, D>,
    right_raw_c: Element<'dr, D>,
    left_app: Element<'dr, D>,
    right_app: Element<'dr, D>,
    left_bridge: Element<'dr, D>,
    right_bridge: Element<'dr, D>,
    left_unified: Element<'dr, D>,
    right_unified: Element<'dr, D>,
    zero: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> TwoProofKySource<'dr, D> {
    /// Create a new source from preamble and error_n stage outputs.
    fn new<C: Cycle<CircuitField = D::F>, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>(
        dr: &mut D,
        preamble: &native_preamble::Output<'dr, D, C, HEADER_SIZE>,
        error_n: &native_error_n::Output<'dr, D, FP, C::CircuitPoseidon>,
    ) -> Self {
        Self {
            left_raw_c: preamble.left.unified.c.clone(),
            right_raw_c: preamble.right.unified.c.clone(),
            left_app: error_n.left.application.clone(),
            right_app: error_n.right.application.clone(),
            left_bridge: error_n.left.unified_bridge.clone(),
            right_bridge: error_n.right.unified_bridge.clone(),
            left_unified: error_n.left.unified.clone(),
            right_unified: error_n.right.unified.clone(),
            zero: Element::zero(dr),
        }
    }
}

impl<'dr, D: Driver<'dr>> KySource for TwoProofKySource<'dr, D> {
    type Ky = Element<'dr, D>;

    fn raw_c(&self) -> impl Iterator<Item = Element<'dr, D>> {
        once(self.left_raw_c.clone()).chain(once(self.right_raw_c.clone()))
    }

    fn application_ky(&self) -> impl Iterator<Item = Element<'dr, D>> {
        once(self.left_app.clone()).chain(once(self.right_app.clone()))
    }

    fn unified_bridge_ky(&self) -> impl Iterator<Item = Element<'dr, D>> {
        once(self.left_bridge.clone()).chain(once(self.right_bridge.clone()))
    }

    fn unified_ky(&self) -> impl Iterator<Item = Element<'dr, D>> + Clone {
        once(self.left_unified.clone()).chain(once(self.right_unified.clone()))
    }

    fn zero(&self) -> Element<'dr, D> {
        self.zero.clone()
    }
}
