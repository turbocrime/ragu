use arithmetic::{Cycle, PrimeFieldExt};
use ff::Field;
use ragu_circuits::{
    CircuitExt,
    polynomials::Rank,
    staging::{Stage, StageExt},
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{
    Element, GadgetExt, Point,
    poseidon::Sponge,
    vec::{CollectFixed, FixedVec},
};
use rand::Rng;

use alloc::vec;

use crate::{
    Application,
    components::fold_revdot::{self, NativeParameters},
    internal_circuits::{
        self,
        stages::{self, native::error_n::KyValues},
        total_circuit_counts, unified,
    },
    proof::{
        ABProof, ApplicationProof, Challenges, CircuitCommitments, ErrorMProof, ErrorNProof,
        EvalProof, FProof, Pcd, PreambleProof, Proof, QueryProof, SPrimeProof,
    },
    step::{Step, adapter::Adapter},
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Fuse two [`Pcd`] into one using a provided [`Step`].
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
    /// * `left`: the left [`Pcd`] to fuse in this step; must correspond to the
    ///   [`Step::Left`] header.
    /// * `right`: the right [`Pcd`] to fuse in this step; must correspond to
    ///   the [`Step::Right`] header.
    pub fn fuse<'source, RNG: Rng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<'source, C, R, S::Left>,
        right: Pcd<'source, C, R, S::Right>,
    ) -> Result<(Proof<C, R>, S::Aux<'source>)> {
        // Compute the application circuit's witness first, since it processes
        // the data fields of the two proofs being fused.
        let (left, right, application, application_aux) =
            self.compute_application_proof(rng, step, witness, left, right)?;

        // The two proofs being fused are checked simultaneously as part of the
        // same transcript. We simulate this transcript with an `Emulator` in
        // order to construct valid witnesses for the circuits that certify the
        // fuse operation.
        let mut dr = Emulator::execute();
        let mut transcript = Sponge::new(&mut dr, C::circuit_poseidon(self.params));

        // Compute the preamble, the first prover messages in the transcript
        // that bind to the common inputs of the protocol.
        let (preamble, preamble_witness) =
            self.compute_preamble(rng, &left, &right, &application)?;
        Point::constant(&mut dr, preamble.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let w = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 3: S' commitment to m(w, x_i, Y).
        let s_prime = self.compute_s_prime(rng, w, &left, &right)?;
        Point::constant(&mut dr, s_prime.nested_s_prime_commitment)?
            .write(&mut dr, &mut transcript)?;
        let y = *transcript.squeeze(&mut dr)?.value().take();
        let z = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 4: Error M with mesh_wy (Layer 1: N instances of M-sized reductions).
        let (error_m, error_m_witness) = self.compute_error_m(rng, w, y)?;
        Point::constant(&mut dr, error_m.nested_commitment)?.write(&mut dr, &mut transcript)?;

        // Save a copy of the transcript state. This is used as part of the
        // witness for the error_n stage, so that the hashes_2 circuit can
        // resume the sponge state from the end of hashes_1.
        let saved_transcript_state = transcript
            .clone()
            .save_state(&mut dr)
            .expect("save_state should succeed after absorbing")
            .into_elements()
            .into_iter()
            .map(|e| *e.value().take())
            .collect_fixed()?;

        let mu = *transcript.squeeze(&mut dr)?.value().take();
        let nu = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 5: Error N (k(y) computation, layer 1 folding, and N-sized reduction).
        let (error_n, error_n_witness) = self.compute_error_n(
            rng,
            &preamble_witness,
            &error_m_witness,
            y,
            mu,
            nu,
            saved_transcript_state,
        )?;

        // Derive (mu', nu') = H(nested_error_n_commitment).
        Point::constant(&mut dr, error_n.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let mu_prime = *transcript.squeeze(&mut dr)?.value().take();
        let nu_prime = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 6: Compute C, the folded revdot product claim.
        let c = self.compute_c(mu_prime, nu_prime, &error_n_witness)?;

        // Phase 7: A/B polynomials.
        let ab = self.compute_ab(rng)?;

        // Derive x = H(nested_ab_commitment).
        Point::constant(&mut dr, ab.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let x = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 8: Query with mesh_xy.
        let query = self.compute_query(rng, x, y)?;

        // Derive alpha = H(nested_query_commitment).
        Point::constant(&mut dr, query.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let alpha = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 9: F polynomial.
        let f = self.compute_f(rng)?;

        // Derive u = H(nested_f_commitment).
        Point::constant(&mut dr, f.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let u = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 10: Eval.
        let eval = self.compute_eval(rng)?;
        Point::constant(&mut dr, eval.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let beta = *transcript.squeeze(&mut dr)?.value().take();

        // Phase 11: Challenges.
        let challenges = Challenges {
            w,
            y,
            z,
            mu,
            nu,
            mu_prime,
            nu_prime,
            c,
            x,
            alpha,
            u,
            beta,
        };

        // Phase 12: Internal circuits.
        let circuits = self.compute_internal_circuits(
            rng,
            &preamble,
            &s_prime,
            &error_m,
            &error_n,
            &ab,
            &query,
            &f,
            &eval,
            &preamble_witness,
            &error_m_witness,
            &error_n_witness,
            &challenges,
        )?;

        Ok((
            Proof {
                application,
                preamble,
                s_prime,
                error_m,
                error_n,
                ab,
                query,
                f,
                eval,
                challenges,
                circuits,
            },
            // We return the application auxiliary data for potential use by the
            // caller.
            application_aux,
        ))
    }

    /// Compute the application circuit proof.
    ///
    /// We process the application circuit first because it consumes the
    /// `Pcd`'s `data` fields inside of the `Step` circuit. The adapter
    /// handles encoding for us, so that we can use the resulting (encoded)
    /// headers to construct the proof. We can also then use the encoded
    /// headers later to construct witnesses for other internal circuits
    /// constructed during the fuse operation.
    ///
    /// Returns the enclosed left/right `Proof` structures along with the
    /// application proof and auxiliary data.
    fn compute_application_proof<'source, RNG: Rng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<'source, C, R, S::Left>,
        right: Pcd<'source, C, R, S::Right>,
    ) -> Result<(
        Proof<C, R>,
        Proof<C, R>,
        ApplicationProof<C, R>,
        S::Aux<'source>,
    )> {
        let circuit_id = S::INDEX.circuit_index(self.num_application_steps)?;
        let (rx, aux) = Adapter::<C, S, R, HEADER_SIZE>::new(step).rx::<R>(
            (left.data, right.data, witness),
            self.circuit_mesh.get_key(),
        )?;
        let blind = C::CircuitField::random(&mut *rng);
        let commitment = rx.commit(C::host_generators(self.params), blind);

        let ((left_header, right_header), aux) = aux;

        Ok((
            left.proof,
            right.proof,
            ApplicationProof {
                circuit_id,
                left_header: left_header.into_inner(),
                right_header: right_header.into_inner(),
                rx,
                blind,
                commitment,
            },
            aux,
        ))
    }

    /// Compute the preamble proof.
    ///
    /// The preamble stage commits to all of the `C::CircuitField` elements used
    /// as public inputs to the circuits being fused together. This includes the
    /// unified instance values for both proofs, but also their circuit IDs (the
    /// ω^j value that corresponds to each element of the mesh domain that
    /// corresponds to the Step circuit being checked).
    fn compute_preamble<'a, RNG: Rng>(
        &self,
        rng: &mut RNG,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        application: &ApplicationProof<C, R>,
    ) -> Result<(
        PreambleProof<C, R>,
        stages::native::preamble::Witness<'a, C, R, HEADER_SIZE>,
    )> {
        // Let's assemble the witness needed to generate the preamble stage.
        let preamble_witness = stages::native::preamble::Witness::new(
            left,
            right,
            &application.left_header,
            &application.right_header,
        )?;

        // Now, compute the partial witness polynomial (stage polynomial) for
        // the preamble.
        let stage_rx = stages::native::preamble::Stage::<C, R, HEADER_SIZE>::rx(&preamble_witness)?;
        // ... and commit to it, with a random blinding factor.
        let stage_blind = C::CircuitField::random(&mut *rng);
        let stage_commitment = stage_rx.commit(C::host_generators(self.params), stage_blind);

        // In order to circle back to C::CircuitField, because our
        // `stage_commitment` has base points in C::ScalarField, we
        // need to commit to a stage polynomial over the C::NestedCurve that
        // contains all of the `C::HostCurve` points. This includes the
        // stage_commitment we just computed, but also contains
        // commitments to circuit and stage polynomials that were created in the
        // fuse operations that produced each of the two input proofs.
        let nested_preamble_witness = stages::nested::preamble::Witness {
            native_preamble: stage_commitment,
            left_application: left.application.commitment,
            right_application: right.application.commitment,
            left_ky: left.circuits.ky_commitment,
            right_ky: right.circuits.ky_commitment,
            left_c: left.circuits.c_commitment,
            right_c: right.circuits.c_commitment,
            left_v: left.circuits.v_commitment,
            right_v: right.circuits.v_commitment,
            left_hashes_1: left.circuits.hashes_1_commitment,
            right_hashes_1: right.circuits.hashes_1_commitment,
            left_hashes_2: left.circuits.hashes_2_commitment,
            right_hashes_2: right.circuits.hashes_2_commitment,
        };

        // Compute the stage polynomial that commits to the `C::HostCurve`
        // points.
        let nested_rx =
            stages::nested::preamble::Stage::<C::HostCurve, R>::rx(&nested_preamble_witness)?;
        // ... and again commit to it, this time producing a point that is
        // represented using base field elements in `C::CircuitField` that we
        // can manipulate as the "native" field.
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok((
            PreambleProof {
                stage_rx,
                stage_blind,
                stage_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            preamble_witness,
        ))
    }

    /// Compute the S' proof.
    ///
    /// In order to check that the two proofs' commitments to s (the mesh
    /// polynomial evaluated at (x_0, y_0) and (x_1, y_1)) are correct, we need
    /// to compute s' = m(w, x_i, Y) for both proofs.
    fn compute_s_prime<RNG: Rng>(
        &self,
        rng: &mut RNG,
        w: C::CircuitField,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<SPrimeProof<C, R>> {
        let x0 = left.challenges.x;
        let x1 = right.challenges.x;

        // ... commit to both...
        let mesh_wx0_poly = self.circuit_mesh.wx(w, x0);
        let mesh_wx0_blind = C::CircuitField::random(&mut *rng);
        let mesh_wx0_commitment =
            mesh_wx0_poly.commit(C::host_generators(self.params), mesh_wx0_blind);
        let mesh_wx1_poly = self.circuit_mesh.wx(w, x1);
        let mesh_wx1_blind = C::CircuitField::random(&mut *rng);
        let mesh_wx1_commitment =
            mesh_wx1_poly.commit(C::host_generators(self.params), mesh_wx1_blind);
        // ... and then compute the nested commitment S' that contains them.
        let nested_s_prime_witness = stages::nested::s_prime::Witness {
            mesh_wx0: mesh_wx0_commitment,
            mesh_wx1: mesh_wx1_commitment,
        };
        let nested_s_prime_rx =
            stages::nested::s_prime::Stage::<C::HostCurve, R>::rx(&nested_s_prime_witness)?;
        let nested_s_prime_blind = C::ScalarField::random(&mut *rng);
        let nested_s_prime_commitment =
            nested_s_prime_rx.commit(C::nested_generators(self.params), nested_s_prime_blind);

        Ok(SPrimeProof {
            mesh_wx0_poly,
            mesh_wx0_blind,
            mesh_wx0_commitment,
            mesh_wx1_poly,
            mesh_wx1_blind,
            mesh_wx1_commitment,
            nested_s_prime_rx,
            nested_s_prime_blind,
            nested_s_prime_commitment,
        })
    }

    /// Compute error_m stage with mesh_wy bundled (Layer 1: N instances of M-sized reductions).
    ///
    /// Given (w, y), computes m(w, X, y), commits to it, then creates the error_m
    /// stage with the mesh_wy commitment bundled into the nested layer.
    fn compute_error_m<RNG: Rng>(
        &self,
        rng: &mut RNG,
        w: C::CircuitField,
        y: C::CircuitField,
    ) -> Result<(
        ErrorMProof<C, R>,
        stages::native::error_m::Witness<C, NativeParameters>,
    )> {
        // Compute mesh_wy components
        let mesh_wy_poly = self.circuit_mesh.wy(w, y);
        let mesh_wy_blind = C::CircuitField::random(&mut *rng);
        let mesh_wy_commitment =
            mesh_wy_poly.commit(C::host_generators(self.params), mesh_wy_blind);

        // Error M stage commitment
        let error_m_witness = stages::native::error_m::Witness::<C, NativeParameters> {
            error_terms: FixedVec::from_fn(|_| FixedVec::from_fn(|_| C::CircuitField::todo())),
        };
        let stage_rx = stages::native::error_m::Stage::<C, R, HEADER_SIZE, NativeParameters>::rx(
            &error_m_witness,
        )?;
        let stage_blind = C::CircuitField::random(&mut *rng);
        let stage_commitment = stage_rx.commit(C::host_generators(self.params), stage_blind);

        // Nested error_m commitment (bundles mesh_wy_commitment + stage_commitment)
        let nested_error_m_witness = stages::nested::error_m::Witness {
            native_error_m: stage_commitment,
            mesh_wy: mesh_wy_commitment,
        };
        let nested_rx =
            stages::nested::error_m::Stage::<C::HostCurve, R>::rx(&nested_error_m_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok((
            ErrorMProof {
                mesh_wy_poly,
                mesh_wy_blind,
                mesh_wy_commitment,
                stage_rx,
                stage_blind,
                stage_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            error_m_witness,
        ))
    }

    /// Compute error_n stage (Layer 2: Single N-sized reduction).
    ///
    /// Computes k(y) values from the preamble witness, performs layer 1 folding
    /// to get collapsed values, then builds the error_n stage witness and
    /// commitments.
    fn compute_error_n<RNG: Rng>(
        &self,
        rng: &mut RNG,
        preamble_witness: &stages::native::preamble::Witness<'_, C, R, HEADER_SIZE>,
        error_m_witness: &stages::native::error_m::Witness<C, NativeParameters>,
        y: C::CircuitField,
        mu: C::CircuitField,
        nu: C::CircuitField,
        sponge_state_elements: FixedVec<
            C::CircuitField,
            ragu_primitives::poseidon::PoseidonStateLen<C::CircuitField, C::CircuitPoseidon>,
        >,
    ) -> Result<(
        ErrorNProof<C, R>,
        stages::native::error_n::Witness<C, NativeParameters>,
    )> {
        let (ky, collapsed) = Emulator::emulate_wireless(
            (preamble_witness, &error_m_witness.error_terms, y, mu, nu),
            |dr, witness| {
                let (preamble_witness, error_terms_m, y, mu, nu) = witness.cast();

                // Run preamble stage to get proof inputs.
                let preamble = stages::native::preamble::Stage::<C, R, HEADER_SIZE>::default()
                    .witness(dr, preamble_witness.view().map(|w| *w))?;

                // Compute k(y) values.
                let y = Element::alloc(dr, y)?;
                let left_application_ky = preamble.left.application_ky(dr, &y)?;
                let right_application_ky = preamble.right.application_ky(dr, &y)?;
                let (left_unified_ky, left_unified_bridge_ky) =
                    preamble.left.unified_ky_values(dr, &y)?;
                let (right_unified_ky, right_unified_bridge_ky) =
                    preamble.right.unified_ky_values(dr, &y)?;

                // Compute collapsed values using the k(y) elements directly.
                let mu = Element::alloc(dr, mu)?;
                let nu = Element::alloc(dr, nu)?;

                let mut ky_elements = vec![
                    left_application_ky.clone(),
                    right_application_ky.clone(),
                    left_unified_ky.clone(),
                    right_unified_ky.clone(),
                    left_unified_bridge_ky.clone(),
                    right_unified_bridge_ky.clone(),
                ]
                .into_iter();

                let fold_c = fold_revdot::FoldC::new(dr, &mu, &nu)?;

                let collapsed = FixedVec::try_from_fn(|i| {
                    let errors = FixedVec::try_from_fn(|j| {
                        Element::alloc(dr, error_terms_m.view().map(|et| et[i][j]))
                    })?;
                    let ky_values = FixedVec::from_fn(|_| {
                        ky_elements.next().unwrap_or_else(|| Element::zero(dr))
                    });

                    let v = fold_c.compute_m::<NativeParameters>(dr, &errors, &ky_values)?;
                    Ok(*v.value().take())
                })?;

                // Extract k(y) scalar values.
                let ky = KyValues {
                    left_application: *left_application_ky.value().take(),
                    right_application: *right_application_ky.value().take(),
                    left_unified: *left_unified_ky.value().take(),
                    right_unified: *right_unified_ky.value().take(),
                    left_unified_bridge: *left_unified_bridge_ky.value().take(),
                    right_unified_bridge: *right_unified_bridge_ky.value().take(),
                };

                Ok((ky, collapsed))
            },
        )?;

        let error_n_witness = stages::native::error_n::Witness::<C, NativeParameters> {
            error_terms: FixedVec::from_fn(|_| C::CircuitField::todo()),
            collapsed,
            ky,
            sponge_state_elements,
        };
        let stage_rx = stages::native::error_n::Stage::<C, R, HEADER_SIZE, NativeParameters>::rx(
            &error_n_witness,
        )?;
        let stage_blind = C::CircuitField::random(&mut *rng);
        let stage_commitment = stage_rx.commit(C::host_generators(self.params), stage_blind);

        // Nested error_n commitment
        let nested_error_n_witness = stages::nested::error_n::Witness {
            native_error_n: stage_commitment,
        };
        let nested_rx =
            stages::nested::error_n::Stage::<C::HostCurve, R>::rx(&nested_error_n_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok((
            ErrorNProof {
                stage_rx,
                stage_blind,
                stage_commitment,
                nested_rx,
                nested_blind,
                nested_commitment,
            },
            error_n_witness,
        ))
    }

    /// Compute c, the folded revdot product claim (layer 2 only).
    ///
    /// Performs a single N-sized reduction using the collapsed values from
    /// layer 1 as the k(y) values.
    fn compute_c(
        &self,
        mu_prime: C::CircuitField,
        nu_prime: C::CircuitField,
        error_n_witness: &stages::native::error_n::Witness<C, NativeParameters>,
    ) -> Result<C::CircuitField> {
        Emulator::emulate_wireless(
            (
                mu_prime,
                nu_prime,
                &error_n_witness.error_terms,
                &error_n_witness.collapsed,
            ),
            |dr, witness| {
                let (mu_prime, nu_prime, error_terms_n, collapsed) = witness.cast();

                let mu_prime = Element::alloc(dr, mu_prime)?;
                let nu_prime = Element::alloc(dr, nu_prime)?;

                let error_terms_n = FixedVec::try_from_fn(|i| {
                    Element::alloc(dr, error_terms_n.view().map(|et| et[i]))
                })?;

                let collapsed =
                    FixedVec::try_from_fn(|i| Element::alloc(dr, collapsed.view().map(|c| c[i])))?;

                // Layer 2: Single N-sized reduction using collapsed as ky_values
                let fold_c = fold_revdot::FoldC::new(dr, &mu_prime, &nu_prime)?;
                let c = fold_c.compute_n::<NativeParameters>(dr, &error_terms_n, &collapsed)?;

                Ok(*c.value().take())
            },
        )
    }

    /// Compute the A/B polynomials proof.
    ///
    /// Commits to A and B polynomials, then creates the nested commitment.
    fn compute_ab<RNG: Rng>(&self, rng: &mut RNG) -> Result<ABProof<C, R>> {
        // TODO: For now, stub out fake A and B polynomials.
        // A polynomial
        let a_poly =
            ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();
        let a_blind = C::CircuitField::random(&mut *rng);
        let a_commitment = a_poly.commit(C::host_generators(self.params), a_blind);

        // B polynomial
        let b_poly =
            ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();
        let b_blind = C::CircuitField::random(&mut *rng);
        let b_commitment = b_poly.commit(C::host_generators(self.params), b_blind);

        let nested_ab_witness = stages::nested::ab::Witness {
            a: a_commitment,
            b: b_commitment,
        };
        let nested_rx = stages::nested::ab::Stage::<C::HostCurve, R>::rx(&nested_ab_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok(ABProof {
            a_poly,
            a_blind,
            a_commitment,
            b_poly,
            b_blind,
            b_commitment,
            nested_rx,
            nested_blind,
            nested_commitment,
        })
    }

    /// Compute query proof with mesh_xy bundled.
    ///
    /// Computes m(x, y), commits to it, then creates native and nested query commitments
    /// with the mesh_xy commitment bundled into the nested layer.
    fn compute_query<RNG: Rng>(
        &self,
        rng: &mut RNG,
        x: C::CircuitField,
        y: C::CircuitField,
    ) -> Result<QueryProof<C, R>> {
        // Compute mesh_xy components
        let mesh_xy_poly = self.circuit_mesh.xy(x, y);
        let mesh_xy_blind = C::CircuitField::random(&mut *rng);
        let mesh_xy_commitment =
            mesh_xy_poly.commit(C::host_generators(self.params), mesh_xy_blind);

        // Query stage commitment
        let query_witness = internal_circuits::stages::native::query::Witness {
            queries: FixedVec::from_fn(|_| C::CircuitField::todo()),
        };

        let stage_rx = internal_circuits::stages::native::query::Stage::<C, R, HEADER_SIZE>::rx(
            &query_witness,
        )?;
        let stage_blind = C::CircuitField::random(&mut *rng);
        let stage_commitment = stage_rx.commit(C::host_generators(self.params), stage_blind);

        // Nested query commitment (bundles mesh_xy_commitment + stage_commitment)
        let nested_query_witness = stages::nested::query::Witness {
            native_query: stage_commitment,
            mesh_xy: mesh_xy_commitment,
        };
        let nested_rx = stages::nested::query::Stage::<C::HostCurve, R>::rx(&nested_query_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok(QueryProof {
            mesh_xy_poly,
            mesh_xy_blind,
            mesh_xy_commitment,
            stage_rx,
            stage_blind,
            stage_commitment,
            nested_rx,
            nested_blind,
            nested_commitment,
        })
    }

    /// Compute the F polynomial proof.
    fn compute_f<RNG: Rng>(&self, rng: &mut RNG) -> Result<FProof<C, R>> {
        let poly = ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();
        let blind = C::CircuitField::random(&mut *rng);
        let commitment = poly.commit(C::host_generators(self.params), blind);

        let nested_f_witness = internal_circuits::stages::nested::f::Witness {
            native_f: commitment,
        };
        let nested_rx =
            internal_circuits::stages::nested::f::Stage::<C::HostCurve, R>::rx(&nested_f_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok(FProof {
            poly,
            blind,
            commitment,
            nested_rx,
            nested_blind,
            nested_commitment,
        })
    }

    /// Compute the eval proof.
    fn compute_eval<RNG: Rng>(&self, rng: &mut RNG) -> Result<EvalProof<C, R>> {
        let eval_witness = internal_circuits::stages::native::eval::Witness {
            evals: FixedVec::from_fn(|_| C::CircuitField::todo()),
        };
        let stage_rx =
            internal_circuits::stages::native::eval::Stage::<C, R, HEADER_SIZE>::rx(&eval_witness)?;
        let stage_blind = C::CircuitField::random(&mut *rng);
        let stage_commitment = stage_rx.commit(C::host_generators(self.params), stage_blind);

        let nested_eval_witness = internal_circuits::stages::nested::eval::Witness {
            native_eval: stage_commitment,
        };
        let nested_rx = internal_circuits::stages::nested::eval::Stage::<C::HostCurve, R>::rx(
            &nested_eval_witness,
        )?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok(EvalProof {
            stage_rx,
            stage_blind,
            stage_commitment,
            nested_rx,
            nested_blind,
            nested_commitment,
        })
    }

    /// Compute internal circuits.
    fn compute_internal_circuits<RNG: Rng>(
        &self,
        rng: &mut RNG,
        preamble: &PreambleProof<C, R>,
        s_prime: &SPrimeProof<C, R>,
        error_m: &ErrorMProof<C, R>,
        error_n: &ErrorNProof<C, R>,
        ab: &ABProof<C, R>,
        query: &QueryProof<C, R>,
        f: &FProof<C, R>,
        eval: &EvalProof<C, R>,
        preamble_witness: &stages::native::preamble::Witness<'_, C, R, HEADER_SIZE>,
        error_m_witness: &stages::native::error_m::Witness<C, NativeParameters>,
        error_n_witness: &stages::native::error_n::Witness<C, NativeParameters>,
        challenges: &Challenges<C>,
    ) -> Result<CircuitCommitments<C, R>> {
        // Build unified instance from proof structs and challenges.
        let unified_instance = &unified::Instance {
            nested_preamble_commitment: preamble.nested_commitment,
            w: challenges.w,
            nested_s_prime_commitment: s_prime.nested_s_prime_commitment,
            y: challenges.y,
            z: challenges.z,
            nested_error_m_commitment: error_m.nested_commitment,
            mu: challenges.mu,
            nu: challenges.nu,
            nested_error_n_commitment: error_n.nested_commitment,
            mu_prime: challenges.mu_prime,
            nu_prime: challenges.nu_prime,
            c: challenges.c,
            nested_ab_commitment: ab.nested_commitment,
            x: challenges.x,
            nested_query_commitment: query.nested_commitment,
            alpha: challenges.alpha,
            nested_f_commitment: f.nested_commitment,
            u: challenges.u,
            nested_eval_commitment: eval.nested_commitment,
            beta: challenges.beta,
        };

        // compute_c staged circuit.
        let (c_rx, _) =
            internal_circuits::compute_c::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new()
                .rx::<R>(
                    internal_circuits::compute_c::Witness {
                        unified_instance,
                        preamble_witness,
                        error_m_witness,
                        error_n_witness,
                    },
                    self.circuit_mesh.get_key(),
                )?;
        let c_rx_blind = C::CircuitField::random(&mut *rng);
        let c_rx_commitment = c_rx.commit(C::host_generators(self.params), c_rx_blind);

        // compute_v staged circuit.
        let (v_rx, _) = internal_circuits::compute_v::Circuit::<C, R, HEADER_SIZE>::new().rx::<R>(
            internal_circuits::compute_v::Witness { unified_instance },
            self.circuit_mesh.get_key(),
        )?;
        let v_rx_blind = C::CircuitField::random(&mut *rng);
        let v_rx_commitment = v_rx.commit(C::host_generators(self.params), v_rx_blind);

        // Hashes_1 staged circuit.
        let (hashes_1_rx, _) =
            internal_circuits::hashes_1::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(
                self.params,
                total_circuit_counts(self.num_application_steps).1,
            )
            .rx::<R>(
                internal_circuits::hashes_1::Witness {
                    unified_instance,
                    preamble_witness,
                    error_n_witness,
                },
                self.circuit_mesh.get_key(),
            )?;
        let hashes_1_rx_blind = C::CircuitField::random(&mut *rng);
        let hashes_1_rx_commitment =
            hashes_1_rx.commit(C::host_generators(self.params), hashes_1_rx_blind);

        // Hashes_2 staged circuit.
        let (hashes_2_rx, _) =
            internal_circuits::hashes_2::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(
                self.params,
            )
            .rx::<R>(
                internal_circuits::hashes_2::Witness {
                    unified_instance,
                    error_n_witness,
                },
                self.circuit_mesh.get_key(),
            )?;
        let hashes_2_rx_blind = C::CircuitField::random(&mut *rng);
        let hashes_2_rx_commitment =
            hashes_2_rx.commit(C::host_generators(self.params), hashes_2_rx_blind);

        // fold staged circuit (layer 1 folding verification).
        let (ky_rx, _) =
            internal_circuits::fold::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new()
                .rx::<R>(
                    internal_circuits::fold::Witness {
                        unified_instance,
                        error_m_witness,
                        error_n_witness,
                    },
                    self.circuit_mesh.get_key(),
                )?;
        let ky_rx_blind = C::CircuitField::random(&mut *rng);
        let ky_rx_commitment = ky_rx.commit(C::host_generators(self.params), ky_rx_blind);

        Ok(CircuitCommitments {
            c_rx,
            c_blind: c_rx_blind,
            c_commitment: c_rx_commitment,
            v_rx,
            v_blind: v_rx_blind,
            v_commitment: v_rx_commitment,
            hashes_1_rx,
            hashes_1_blind: hashes_1_rx_blind,
            hashes_1_commitment: hashes_1_rx_commitment,
            hashes_2_rx,
            hashes_2_blind: hashes_2_rx_blind,
            hashes_2_commitment: hashes_2_rx_commitment,
            ky_rx,
            ky_blind: ky_rx_blind,
            ky_commitment: ky_rx_commitment,
        })
    }
}
