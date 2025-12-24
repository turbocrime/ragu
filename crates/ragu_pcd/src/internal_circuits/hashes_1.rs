//! First hash circuit for Fiat-Shamir derivations (claim-side challenges).
//!
//! This circuit derives the first part of the Fiat-Shamir transcript:
//! - `w = H(nested_preamble_commitment)`
//! - `(y, z) = H(w, nested_s_prime_commitment)`
//! - Absorbs `nested_error_m_commitment` and verifies saved sponge state
//!
//! The remaining challenges (mu, nu, mu_prime, nu_prime, x, alpha, u, beta) are
//! derived in hashes_2 by resuming from the saved sponge state.
//!
//! This circuit also provides the bridge binding between ApplicationProof headers
//! and preamble output headers by including headers in its output. The verifier
//! computes k(y) from ApplicationProof headers, and verification ensures these
//! match the preamble headers output by the circuit.

use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, GadgetExt,
    io::Write,
    poseidon::Sponge,
    vec::{ConstLen, FixedVec},
};

use core::marker::PhantomData;

use super::{
    stages::native::{
        error_m as native_error_m, error_n as native_error_n, preamble as native_preamble,
    },
    unified::{self, OutputBuilder},
};
use crate::components::{fold_revdot, root_of_unity, suffix::Suffix};

pub use crate::internal_circuits::InternalCircuitIndex::Hashes1Circuit as CIRCUIT_ID;
pub use crate::internal_circuits::InternalCircuitIndex::Hashes1Staged as STAGED_ID;

/// Output: headers + unified instance for bridge binding.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Cycle, const HEADER_SIZE: usize> {
    #[ragu(gadget)]
    pub unified: unified::Output<'dr, D, C>,
    #[ragu(gadget)]
    pub left_header: FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>,
    #[ragu(gadget)]
    pub right_header: FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>,
}

#[allow(type_alias_bounds)]
pub type OutputKind<C: Cycle, const HEADER_SIZE: usize> =
    Kind![C::CircuitField; Suffix<'_, _, Output<'_, _, C, HEADER_SIZE>>];

pub struct Circuit<'params, C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    params: &'params C,
    log2_circuits: u32,
    _marker: PhantomData<(R, FP)>,
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    Circuit<'params, C, R, HEADER_SIZE, FP>
{
    pub fn new(params: &'params C, log2_circuits: u32) -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            params,
            log2_circuits,
            _marker: PhantomData,
        })
    }
}

pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    pub unified_instance: &'a unified::Instance<C>,
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    pub error_m_witness: &'a native_error_m::Witness<C, FP>,
    pub error_n_witness: &'a native_error_n::Witness<C, FP>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    StagedCircuit<C::CircuitField, R> for Circuit<'_, C, R, HEADER_SIZE, FP>
{
    type Final = native_error_n::Stage<C, R, HEADER_SIZE, FP>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE, FP>;
    type Output = OutputKind<C, HEADER_SIZE>;
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
        let (error_m, builder) =
            builder.add_stage::<native_error_m::Stage<C, R, HEADER_SIZE, FP>>()?;
        let (error_n, builder) =
            builder.add_stage::<native_error_n::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();

        let preamble = preamble.enforced(dr, witness.view().map(|w| w.preamble_witness))?;
        let _error_m = error_m.enforced(dr, witness.view().map(|w| w.error_m_witness))?;
        let error_n = error_n.enforced(dr, witness.view().map(|w| w.error_n_witness))?;

        // Verify circuit IDs are valid roots of unity in the mesh domain.
        root_of_unity::enforce(dr, preamble.left.circuit_id.clone(), self.log2_circuits)?;
        root_of_unity::enforce(dr, preamble.right.circuit_id.clone(), self.log2_circuits)?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Create a single long-lived sponge for all challenge derivations
        let mut sponge = Sponge::new(dr, self.params.circuit_poseidon());

        // Derive w by absorbing nested_preamble_commitment and squeezing
        let w = {
            let nested_preamble_commitment = unified_output
                .nested_preamble_commitment
                .get(dr, unified_instance)?;
            nested_preamble_commitment.write(dr, &mut sponge)?;
            sponge.squeeze(dr)?
        };
        unified_output.w.set(w.clone());

        // Derive (y, z) by absorbing nested_s_prime_commitment and squeezing twice
        let (y, z) = {
            let nested_s_prime_commitment = unified_output
                .nested_s_prime_commitment
                .get(dr, unified_instance)?;
            nested_s_prime_commitment.write(dr, &mut sponge)?;
            let y = sponge.squeeze(dr)?;
            let z = sponge.squeeze(dr)?;
            (y, z)
        };
        unified_output.y.set(y.clone());
        unified_output.z.set(z);

        // Compute k(y) values from preamble and enforce equality with staged
        // values.
        {
            let left_application_ky = preamble.left.application_ky(dr, &y)?;
            let right_application_ky = preamble.right.application_ky(dr, &y)?;

            left_application_ky.enforce_equal(dr, &error_n.left_application_ky)?;
            right_application_ky.enforce_equal(dr, &error_n.right_application_ky)?;

            let (left_unified_ky, left_unified_bridge_ky) =
                preamble.left.unified_ky_values(dr, &y)?;
            let (right_unified_ky, right_unified_bridge_ky) =
                preamble.right.unified_ky_values(dr, &y)?;

            left_unified_ky.enforce_equal(dr, &error_n.left_unified_ky)?;
            right_unified_ky.enforce_equal(dr, &error_n.right_unified_ky)?;
            left_unified_bridge_ky.enforce_equal(dr, &error_n.left_unified_bridge_ky)?;
            right_unified_bridge_ky.enforce_equal(dr, &error_n.right_unified_bridge_ky)?;
        }

        // Absorb nested_error_m_commitment and verify saved sponge state
        // (mu, nu, mu_prime, nu_prime derivation moved to hashes_2)
        {
            let nested_error_m_commitment = unified_output
                .nested_error_m_commitment
                .get(dr, unified_instance)?;
            nested_error_m_commitment.write(dr, &mut sponge)?;

            // Save state and verify it matches the witnessed state from error_n
            sponge
                .save_state(dr)
                .expect("save_state should succeed after absorbing")
                .enforce_equal(dr, &error_n.sponge_state)?;
        }

        // Output headers from preamble + unified instance.
        // Verification with `unified_bridge_ky` ensures preamble headers match
        // ApplicationProof headers.
        let output = Output {
            left_header: preamble.left.output_header,
            right_header: preamble.right.output_header,
            unified: unified_output.finish_no_suffix(dr, unified_instance)?,
        };

        let zero = Element::zero(dr);
        Ok((Suffix::new(output, zero), D::just(|| ())))
    }
}
