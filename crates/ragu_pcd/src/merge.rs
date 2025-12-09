use alloc::vec::Vec;
use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{CircuitExt, mesh::omega_j, polynomials::Rank, staging::StageExt};
use ragu_core::{Error, Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{
    Element,
    vec::{CollectFixed, FixedVec, Len},
};
use rand::Rng;

use crate::{
    Application,
    components::fold_revdot::{self, ErrorTermsLen},
    internal_circuits::{self, NUM_REVDOT_CLAIMS, stages::native::preamble},
    proof::{ApplicationProof, InternalCircuits, Pcd, PreambleProof, Proof},
    step::{Step, adapter::Adapter},
    verify::stub_step::StubStep,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Merge two PCD into one using a provided [`Step`].
    ///
    /// ## Parameters
    ///
    /// * `rng`: a random number generator used to sample randomness during
    ///   proof generation. The fact that this method takes a random number
    ///   generator is not an indication that the resulting proof-carrying data
    ///   is zero-knowledge; that must be ensured by performing
    ///   [`Application::rerandomize`] at a later point.
    /// * `step`: the [`Step`] instance that has been registered in this
    ///   [`Application`].
    /// * `witness`: the witness data for the [`Step`]
    /// * `left`: the left PCD to merge in this step; must correspond to the
    ///   [`Step::Left`] header.
    /// * `right`: the right PCD to merge in this step; must correspond to the
    ///   [`Step::Right`] header.
    pub fn merge<'source, RNG: Rng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<'source, C, R, S::Left>,
        right: Pcd<'source, C, R, S::Right>,
    ) -> Result<(Proof<C, R>, S::Aux<'source>)> {
        let host_generators = self.params.host_generators();
        let nested_generators = self.params.nested_generators();

        // Reconstruct k(Y) public input polynomial for the left and right PCDs.
        let left_ky_poly = {
            let adapter = Adapter::<C, StubStep<S::Left>, R, HEADER_SIZE>::new(StubStep::new());
            let left_header = FixedVec::try_from(left.proof.application.left_header)
                .map_err(|_| Error::MalformedEncoding("left header size".into()))?;
            let right_header = FixedVec::try_from(left.proof.application.right_header)
                .map_err(|_| Error::MalformedEncoding("right header size".into()))?;
            adapter.ky((left_header, right_header, left.data.clone()))?
        };

        let right_ky_poly = {
            let adapter = Adapter::<C, StubStep<S::Right>, R, HEADER_SIZE>::new(StubStep::new());
            let left_header = FixedVec::try_from(right.proof.application.left_header)
                .map_err(|_| Error::MalformedEncoding("left header size".into()))?;
            let right_header = FixedVec::try_from(right.proof.application.right_header)
                .map_err(|_| Error::MalformedEncoding("right header size".into()))?;
            adapter.ky((left_header, right_header, right.data.clone()))?
        };

        // Extract headers from k(Y) polynomials.
        fn extract_headers<F: Copy, const HEADER_SIZE: usize>(
            ky_poly: Vec<F>,
        ) -> preamble::ProofHeaders<F, HEADER_SIZE> {
            let mut right_header = [ky_poly[0]; HEADER_SIZE];
            let mut left_header = [ky_poly[0]; HEADER_SIZE];
            let mut output_header = [ky_poly[0]; HEADER_SIZE];

            for i in 0..HEADER_SIZE {
                right_header[i] = ky_poly[i];
                left_header[i] = ky_poly[HEADER_SIZE + i];
                output_header[i] = ky_poly[2 * HEADER_SIZE + i];
            }

            preamble::ProofHeaders {
                right_header,
                left_header,
                output_header,
            }
        }

        let preamble_witness = preamble::Witness {
            left: extract_headers::<C::CircuitField, HEADER_SIZE>(left_ky_poly),
            right: extract_headers::<C::CircuitField, HEADER_SIZE>(right_ky_poly),
            // Circuit IDs from left / right proofs
            left_circuit_id: omega_j(left.proof.application.circuit_id as u32),
            right_circuit_id: omega_j(right.proof.application.circuit_id as u32),
            // Unified instance data from left proof
            left_w: left.proof.internal_circuits.w,
            left_c: left.proof.internal_circuits.c,
            left_mu: left.proof.internal_circuits.mu,
            left_nu: left.proof.internal_circuits.nu,
            // Unified instance data from right proof
            right_w: right.proof.internal_circuits.w,
            right_c: right.proof.internal_circuits.c,
            right_mu: right.proof.internal_circuits.mu,
            right_nu: right.proof.internal_circuits.nu,
        };

        // Compute native preamble
        let native_preamble_rx = preamble::Stage::<C, R, HEADER_SIZE>::rx(&preamble_witness)?;
        let native_preamble_blind = C::CircuitField::random(&mut *rng);
        let native_preamble_commitment =
            native_preamble_rx.commit(host_generators, native_preamble_blind);

        let nested_preamble_points: [C::HostCurve; 5] = [
            native_preamble_commitment,
            left.proof.application.commitment,
            right.proof.application.commitment,
            left.proof.internal_circuits.c_rx_commitment,
            right.proof.internal_circuits.c_rx_commitment,
        ];

        // Compute nested preamble
        let nested_preamble_rx =
            internal_circuits::stages::nested::preamble::Stage::<C::HostCurve, R, 5>::rx(
                &nested_preamble_points,
            )?;
        let nested_preamble_blind: <C as Cycle>::ScalarField = C::ScalarField::random(&mut *rng);
        let nested_preamble_commitment =
            nested_preamble_rx.commit(nested_generators, nested_preamble_blind);

        // Compute w = H(nested_preamble_commitment)
        let w =
            crate::components::transcript::emulate_w::<C>(nested_preamble_commitment, self.params)?;

        // Generate dummy values for mu, nu, and error_terms (for now – these will be derived challenges)
        let mu = C::CircuitField::random(&mut *rng);
        let nu = C::CircuitField::random(&mut *rng);

        let error_terms = ErrorTermsLen::<NUM_REVDOT_CLAIMS>::range()
            .map(|_| C::CircuitField::random(&mut *rng))
            .collect_fixed()?;

        // Compute c by running the routine in a wireless emulator
        let c: C::CircuitField =
            Emulator::emulate_wireless((mu, nu, &error_terms), |dr, witness| {
                let (mu, nu, error_terms) = witness.cast();

                let mu = Element::alloc(dr, mu)?;
                let nu = Element::alloc(dr, nu)?;

                let error_terms = ErrorTermsLen::<NUM_REVDOT_CLAIMS>::range()
                    .map(|i| Element::alloc(dr, error_terms.view().map(|et| et[i])))
                    .try_collect_fixed()?;

                // TODO: Use zeros for ky_values for now.
                let ky_values = (0..NUM_REVDOT_CLAIMS)
                    .map(|_| Element::zero(dr))
                    .collect_fixed()?;

                Ok(*fold_revdot::compute_c::<_, NUM_REVDOT_CLAIMS>(
                    dr,
                    &mu,
                    &nu,
                    &error_terms,
                    &ky_values,
                )?
                .value()
                .take())
            })?;

        // Create the unified instance.
        let unified_instance = &internal_circuits::unified::Instance {
            nested_preamble_commitment,
            w,
            c,
            mu,
            nu,
        };

        // C staged circuit.
        let (c_rx, _) =
            internal_circuits::c::Circuit::<C, R, HEADER_SIZE, NUM_REVDOT_CLAIMS>::new(self.params)
                .rx::<R>(
                    internal_circuits::c::Witness {
                        unified_instance,
                        error_terms,
                    },
                    self.circuit_mesh.get_key(),
                )?;
        let c_rx_blinding = C::CircuitField::random(&mut *rng);
        let c_rx_commitment = c_rx.commit(host_generators, c_rx_blinding);

        // Application
        let application_circuit_id = S::INDEX.circuit_index(self.num_application_steps)?;
        let (application_rx, aux) = Adapter::<C, S, R, HEADER_SIZE>::new(step).rx::<R>(
            (left.data, right.data, witness),
            self.circuit_mesh.get_key(),
        )?;
        let application_rx_blinding = C::CircuitField::random(&mut *rng);
        let application_rx_commitment =
            application_rx.commit(host_generators, application_rx_blinding);

        let ((left_header, right_header), aux) = aux;

        Ok((
            Proof {
                preamble: PreambleProof {
                    native_preamble_rx,
                    native_preamble_commitment,
                    native_preamble_blind,
                    nested_preamble_rx,
                    nested_preamble_commitment,
                    nested_preamble_blind,
                },
                internal_circuits: InternalCircuits {
                    w,
                    c,
                    c_rx,
                    c_rx_blinding,
                    c_rx_commitment,
                    mu,
                    nu,
                },
                application: ApplicationProof {
                    circuit_id: application_circuit_id,
                    left_header: left_header.into_inner(),
                    right_header: right_header.into_inner(),
                    rx: application_rx,
                    blind: application_rx_blinding,
                    commitment: application_rx_commitment,
                },
            },
            aux,
        ))
    }
}
