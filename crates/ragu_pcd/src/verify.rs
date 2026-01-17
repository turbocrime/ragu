//! This module provides the [`Application::verify`] method implementation.

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{
    mesh::CircuitIndex,
    polynomials::{Rank, structured},
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::Element;
use rand::Rng;

use core::iter::once;

use crate::{
    Application, Pcd, Proof,
    circuits::native::stages::preamble::ProofInputs,
    components::claims::{
        self as claims, ClaimBuilder, ClaimSource, KySource, NativeRxComponent, ky_values,
    },
    header::Header,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Verifies some [`Pcd`] for the provided [`Header`].
    pub fn verify<RNG: Rng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<'_, C, R, H>,
        mut rng: RNG,
    ) -> Result<bool> {
        // Sample verification challenges w, y, and z.
        let w = C::CircuitField::random(&mut rng);
        let y = C::CircuitField::random(&mut rng);
        let z = C::CircuitField::random(&mut rng);

        // Validate that the application circuit_id is within the mesh domain.
        // (Internal circuit IDs are constants and don't need this check.)
        if !self
            .native_mesh
            .circuit_in_domain(pcd.proof.application.circuit_id)
        {
            return Ok(false);
        }

        // Validate that the `left_header` and `right_header` lengths match
        // `HEADER_SIZE`. Alternatively, the `Proof` structure could be
        // parameterized on the `HEADER_SIZE`, but this appeared to be simpler.
        if pcd.proof.application.left_header.len() != HEADER_SIZE
            || pcd.proof.application.right_header.len() != HEADER_SIZE
        {
            return Ok(false);
        }

        // Compute unified k(y), unified_bridge k(y), and application k(y).
        let (unified_ky, unified_bridge_ky, application_ky) =
            Emulator::emulate_wireless((&pcd.proof, pcd.data.clone(), y), |dr, witness| {
                let (proof, data, y) = witness.cast();
                let y = Element::alloc(dr, y)?;
                let proof_inputs =
                    ProofInputs::<_, C, HEADER_SIZE>::alloc_for_verify::<R, H>(dr, proof, data)?;

                let (unified_ky, unified_bridge_ky) = proof_inputs.unified_ky_values(dr, &y)?;
                let unified_ky = *unified_ky.value().take();
                let unified_bridge_ky = *unified_bridge_ky.value().take();
                let application_ky = *proof_inputs.application_ky(dr, &y)?.value().take();

                Ok((unified_ky, unified_bridge_ky, application_ky))
            })?;

        // Build a and b polynomials for each revdot claim.
        let source = SingleProofSource { proof: &pcd.proof };
        let mut builder = ClaimBuilder::new(&self.native_mesh, self.num_application_steps, y, z);
        claims::build(&source, &mut builder)?;

        // Check all revdot claims.
        let revdot_claims = {
            let ky_source = SingleProofKySource {
                raw_c: pcd.proof.ab.c,
                application_ky,
                unified_bridge_ky,
                unified_ky,
            };

            ky_values(&ky_source)
                .zip(builder.a.iter().zip(builder.b.iter()))
                .all(|(ky, (a, b))| a.revdot(b) == ky)
        };

        // Check polynomial evaluation claim.
        let p_eval_claim = pcd.proof.p.poly.eval(pcd.proof.challenges.u) == pcd.proof.p.v;

        // Check P commitment corresponds to polynomial and blind.
        let p_commitment_claim = pcd
            .proof
            .p
            .poly
            .commit(C::host_generators(self.params), pcd.proof.p.blind)
            == pcd.proof.p.commitment;

        // Check mesh_xy polynomial evaluation at the sampled w.
        // mesh_xy_poly is m(W, x, y) - the mesh evaluated at current x, y, free in W.
        let mesh_xy_claim = {
            let x = pcd.proof.challenges.x;
            let y = pcd.proof.challenges.y;
            let poly_eval = pcd.proof.query.mesh_xy_poly.eval(w);
            let expected = self.native_mesh.wxy(w, x, y);
            poly_eval == expected
        };

        // TODO: Add checks for mesh_wx0_poly, mesh_wx1_poly, and mesh_wy_poly.
        // - mesh_wx0/wx1: need child proof x challenges (x₀, x₁) which "disappear" in preamble
        // - mesh_wy: interstitial value that will be elided later

        Ok(revdot_claims && p_eval_claim && p_commitment_claim && mesh_xy_claim)
    }
}

/// Wraps a single proof for use with `ClaimSource`.
struct SingleProofSource<'rx, C: Cycle, R: Rank> {
    proof: &'rx Proof<C, R>,
}

impl<'rx, C: Cycle, R: Rank> ClaimSource for SingleProofSource<'rx, C, R> {
    type Rx = &'rx structured::Polynomial<C::CircuitField, R>;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, component: NativeRxComponent) -> impl Iterator<Item = Self::Rx> {
        let poly = match component {
            NativeRxComponent::AbA => &self.proof.ab.a_poly,
            NativeRxComponent::AbB => &self.proof.ab.b_poly,
            NativeRxComponent::Application => &self.proof.application.rx,
            NativeRxComponent::Hashes1 => &self.proof.circuits.hashes_1_rx,
            NativeRxComponent::Hashes2 => &self.proof.circuits.hashes_2_rx,
            NativeRxComponent::PartialCollapse => &self.proof.circuits.partial_collapse_rx,
            NativeRxComponent::FullCollapse => &self.proof.circuits.full_collapse_rx,
            NativeRxComponent::ComputeV => &self.proof.circuits.compute_v_rx,
            NativeRxComponent::Preamble => &self.proof.preamble.native_rx,
            NativeRxComponent::ErrorM => &self.proof.error_m.native_rx,
            NativeRxComponent::ErrorN => &self.proof.error_n.native_rx,
            NativeRxComponent::Query => &self.proof.query.native_rx,
            NativeRxComponent::Eval => &self.proof.eval.native_rx,
        };
        core::iter::once(poly)
    }

    fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
        core::iter::once(self.proof.application.circuit_id)
    }
}

/// Source for k(y) values for single-proof verification.
struct SingleProofKySource<F> {
    raw_c: F,
    application_ky: F,
    unified_bridge_ky: F,
    unified_ky: F,
}

impl<F: Field> KySource for SingleProofKySource<F> {
    type Ky = F;

    fn raw_c(&self) -> impl Iterator<Item = F> {
        once(self.raw_c)
    }

    fn application_ky(&self) -> impl Iterator<Item = F> {
        once(self.application_ky)
    }

    fn unified_bridge_ky(&self) -> impl Iterator<Item = F> {
        once(self.unified_bridge_ky)
    }

    fn unified_ky(&self) -> impl Iterator<Item = F> + Clone {
        once(self.unified_ky)
    }

    fn zero(&self) -> F {
        F::ZERO
    }
}
