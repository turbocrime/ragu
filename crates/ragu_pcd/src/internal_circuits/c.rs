use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
    maybe::Maybe,
};

use core::marker::PhantomData;

use super::{
    stages::native::{
        error_m as native_error_m, error_n as native_error_n, preamble as native_preamble,
    },
    unified::{self, OutputBuilder},
};
use crate::components::{
    fold_revdot::{self, Parameters},
    root_of_unity,
};

pub use crate::internal_circuits::InternalCircuitIndex::ClaimCircuit as CIRCUIT_ID;
pub use crate::internal_circuits::InternalCircuitIndex::ClaimStaged as STAGED_ID;

pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize, P: Parameters> {
    log2_circuits: u32,
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, P: Parameters> Circuit<C, R, HEADER_SIZE, P> {
    pub fn new(log2_circuits: u32) -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            log2_circuits,
            _marker: PhantomData,
        })
    }
}

pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, P: Parameters> {
    pub unified_instance: &'a unified::Instance<C>,
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    pub error_n_witness: &'a native_error_n::Witness<C, P>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, P: Parameters> StagedCircuit<C::CircuitField, R>
    for Circuit<C, R, HEADER_SIZE, P>
{
    type Final = native_error_n::Stage<C, R, HEADER_SIZE, P>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE, P>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        OutputBuilder::new().finish(dr, &instance)
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
        let builder = builder.skip_stage::<native_error_m::Stage<C, R, HEADER_SIZE, P>>()?;
        let (error_n, builder) =
            builder.add_stage::<native_error_n::Stage<C, R, HEADER_SIZE, P>>()?;
        let dr = builder.finish();

        let preamble = preamble.enforced(dr, witness.view().map(|w| w.preamble_witness))?;
        let error_n = error_n.enforced(dr, witness.view().map(|w| w.error_n_witness))?;

        // Check that circuit IDs are valid domain elements.
        root_of_unity::enforce(dr, preamble.left.circuit_id.clone(), self.log2_circuits)?;
        root_of_unity::enforce(dr, preamble.right.circuit_id.clone(), self.log2_circuits)?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Get mu_prime, nu_prime from unified instance (derived by hashes_1 circuit).
        let mu_prime = unified_output.mu_prime.get(dr, unified_instance)?;
        let nu_prime = unified_output.nu_prime.get(dr, unified_instance)?;

        // Compute c, the folded revdot product claim.
        // Layer 1 folding is verified by circuit_ky; we use error_n.collapsed directly.
        {
            // Layer 2: Single N-sized reduction using collapsed from error_n as ky_values
            let c = fold_revdot::compute_c_n::<_, P>(
                dr,
                &mu_prime,
                &nu_prime,
                &error_n.error_terms,
                &error_n.collapsed,
            )?;
            unified_output.c.set(c);
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
