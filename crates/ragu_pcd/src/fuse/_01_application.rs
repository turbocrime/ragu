//! Evaluate the [`Step`] circuit.
//!
//! This creates a witness for the step circuit given the two input [`Pcd`]s and
//! the step witness. This sets the application fields on the [`ProofBuilder`]
//! and returns the child proofs along with the output data from the step circuit.
//!
//! Poly-query claims raised by the step (via
//! [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query))
//! are enforced natively here: each claim's evaluation is re-checked against
//! its polynomial, and the claimed commitment is re-derived with
//! [`Application::commit_polynomial`]. A claim that does not hold aborts the
//! fuse with [`Error::InvalidWitness`] — the framework refuses to produce a
//! proof for a dishonest witness. Folding the claims into the proof system's
//! $(P, u, v)$ accumulator, so the *merge circuit* enforces them recursively,
//! is deferred work that requires matching poly-query slots in `compute_v` and
//! the nested endoscaling chain.

use ragu_arithmetic::{CryptoRngCore, Cycle};
use ragu_circuits::{CircuitExt, polynomials::Rank, polynomials::sparse};
use ragu_core::{Error, Result};

use crate::{
    Application, Header, Pcd, Proof,
    internal::challenge,
    proof::ProofBuilder,
    step::{
        Step,
        internal::adapter::{Adapter, AdapterAux},
    },
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_application_proof<'source, RNG: CryptoRngCore, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<(
        Proof<C, R>,
        Proof<C, R>,
        <S::Output as Header<C::CircuitField>>::Data,
        S::Aux<'source>,
    )> {
        let (left_proof, left_data) = left.into_parts();
        let (right_proof, right_data) = right.into_parts();
        let (trace, aux) =
            Adapter::<C, S, R, HEADER_SIZE>::new(step, C::circuit_poseidon(self.params))?
                .trace((left_data, right_data, witness))?
                .into_parts();
        let rx = self.native_registry.assemble(
            &trace,
            S::INDEX.circuit_index(self.num_application_steps)?,
            &mut *rng,
        )?;

        let AdapterAux {
            left_header,
            right_header,
            output_data,
            step_aux,
            claims,
        } = aux;

        // Enforce every poly-query claim natively before committing to the
        // proof: the claimed evaluation must hold, and the claimed commitment
        // must bind the claimed polynomial.
        for claim in &claims {
            let poly =
                sparse::Polynomial::<C::CircuitField, R>::from_coeffs(claim.coefficients.clone());
            if poly.eval(claim.x) != claim.y {
                return Err(Error::InvalidWitness(
                    "poly-query claim rejected: the polynomial does not evaluate to the claimed \
                     value at the claimed point"
                        .into(),
                ));
            }
            let expected = challenge::commit_polynomial::<C, R>(self.params, &poly)?;
            if expected != claim.com {
                return Err(Error::InvalidWitness(
                    "poly-query claim rejected: the claimed commitment does not bind the claimed \
                     polynomial"
                        .into(),
                ));
            }
        }

        builder.set_circuit_id(S::INDEX.circuit_index(self.num_application_steps)?);
        builder.set_left_header(left_header.into_inner());
        builder.set_right_header(right_header.into_inner());
        builder.set_native_application_rx(rx);
        builder.set_application_claims(claims);

        Ok((left_proof, right_proof, output_data, step_aux))
    }
}
