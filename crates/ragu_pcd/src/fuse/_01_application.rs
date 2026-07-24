//! Evaluate the [`Step`] circuit.
//!
//! This creates a witness for the step circuit given the two input [`Pcd`]s and
//! the step witness. This sets the application fields on the [`ProofBuilder`]
//! and returns the child proofs along with the output data from the step circuit.
//!
//! Poly-query claims raised by the step (via
//! [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query))
//! are *pre-checked* natively here: each claim's evaluation is re-checked
//! against its polynomial, and the claimed commitment is re-derived with
//! [`Application::commit_polynomial`]. A claim that does not hold aborts the
//! fuse with [`Error::InvalidWitness`] — an honest prover with a dishonest
//! witness fails early instead of producing a proof whose *parent* fuse (which
//! recursively enforces the claims through the PCS accumulator and the
//! `compute_v` circuit) would be unable to open. The claim instances, their
//! polynomials, and their host commitments are recorded on the builder so the
//! parent can fold them.

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
        let (trace, aux) = Adapter::<C, S, R, HEADER_SIZE>::proving(step, self.params)?
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

        // Pre-check every poly-query claim natively before committing to the
        // proof: the claimed evaluation must hold, and the claimed commitment
        // must bind the claimed polynomial. This check carries no soundness
        // weight — it runs on the prover, and a malicious prover who skips it
        // gains nothing, because the parent fuse enforces the same claims
        // through the PCS accumulator and `compute_v`, and the verifier
        // checks a root proof's claims itself. It exists so an honest prover
        // with a dishonest witness fails here, with a useful error, instead
        // of at verification. Along the way, collect the claim polynomials
        // and host commitments the parent's PCS folding will consume.
        assert_eq!(claims.len(), crate::NUM_POLY_QUERY_SLOTS);
        let mut claim_polys = alloc::vec::Vec::with_capacity(claims.len());
        let mut claim_host_commitments = alloc::vec::Vec::with_capacity(claims.len());
        for claim in &claims {
            // Reject an over-capacity coefficient vector gracefully; otherwise
            // `sparse::Polynomial::from_coeffs` would panic on it. Mirrors the
            // guard in `oracle::WitnessedPolynomial::alloc`.
            if claim.coefficients.len() > R::num_coeffs() {
                return Err(Error::InvalidWitness(
                    "poly-query claim rejected: coefficient count exceeds the polynomial rank \
                     capacity"
                        .into(),
                ));
            }
            let poly =
                sparse::Polynomial::<C::CircuitField, R>::from_coeffs(claim.coefficients.clone());
            if poly.eval(claim.x) != claim.y {
                return Err(Error::InvalidWitness(
                    "poly-query claim rejected: the polynomial does not evaluate to the claimed \
                     value at the claimed point"
                        .into(),
                ));
            }
            let (host, expected) = challenge::commit_polynomial_full::<C, R>(self.params, &poly)?;
            #[cfg(feature = "unstable-fuzzing")]
            let precheck = !self.skip_claim_precheck;
            #[cfg(not(feature = "unstable-fuzzing"))]
            let precheck = true;
            if precheck && expected != claim.com {
                return Err(Error::InvalidWitness(
                    "poly-query claim rejected: the claimed commitment does not bind the claimed \
                     polynomial"
                        .into(),
                ));
            }
            claim_polys.push(poly);
            claim_host_commitments.push(host);
        }

        builder.set_circuit_id(S::INDEX.circuit_index(self.num_application_steps)?);
        builder.set_left_header(left_header.into_inner());
        builder.set_right_header(right_header.into_inner());
        builder.set_native_application_rx(rx);
        builder.set_application_claims(claims, claim_polys, claim_host_commitments);

        Ok((left_proof, right_proof, output_data, step_aux))
    }
}
