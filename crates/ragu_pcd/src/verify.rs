//! Proof-carrying data verification.

use arithmetic::{Cycle, eval};
use ff::PrimeField;
use ragu_circuits::{
    CircuitExt,
    mesh::{Mesh, omega_j},
    polynomials::{Rank, structured},
};
use ragu_core::{Error, Result};
use ragu_primitives::vec::{ConstLen, FixedVec};
use rand::Rng;

use crate::{Pcd, header::Header, internal_circuits, step::adapter::Adapter};

mod stub_step;
use stub_step::StubStep;

struct Verifier<'a, F: PrimeField, R: Rank> {
    circuit_mesh: &'a Mesh<'a, F, R>,
    num_application_steps: usize,
    y: F,
    z: F,
    tz: structured::Polynomial<F, R>,
}

impl<'a, F: PrimeField, R: Rank> Verifier<'a, F, R> {
    fn new<RNG: Rng>(
        circuit_mesh: &'a Mesh<'a, F, R>,
        num_application_steps: usize,
        rng: &mut RNG,
    ) -> Self {
        let y = F::random(&mut *rng);
        let z = F::random(&mut *rng);
        let tz = R::tz(z);
        Self {
            circuit_mesh,
            num_application_steps,
            y,
            z,
            tz,
        }
    }

    /// Check an rx polynomial for a stage (empty ky).
    fn check_stage(&self, rx: &structured::Polynomial<F, R>, staging_id: usize) -> bool {
        let circuit_id =
            omega_j(internal_circuits::index(self.num_application_steps, staging_id) as u32);
        let sy = self.circuit_mesh.wy(circuit_id, self.y);

        rx.revdot(&sy) == F::ZERO
    }

    /// Check an rx polynomial for a circuit with computed ky, given a raw circuit_id.
    fn check_circuit(
        &self,
        rx: &structured::Polynomial<F, R>,
        circuit_id: usize,
        ky: &[F],
    ) -> bool {
        self.check_circuit_raw(rx, omega_j(circuit_id as u32), ky)
    }

    /// Check an rx polynomial for an internal circuit with computed ky.
    fn check_internal_circuit(
        &self,
        rx: &structured::Polynomial<F, R>,
        internal_id: usize,
        ky: &[F],
    ) -> bool {
        let circuit_id = internal_circuits::index(self.num_application_steps, internal_id);
        self.check_circuit(rx, circuit_id, ky)
    }

    /// Check an rx polynomial for a circuit with computed ky, given omega_j(circuit_id).
    fn check_circuit_raw(
        &self,
        rx: &structured::Polynomial<F, R>,
        circuit_id: F,
        ky: &[F],
    ) -> bool {
        let sy = self.circuit_mesh.wy(circuit_id, self.y);

        let mut rhs = rx.clone();
        rhs.dilate(self.z);
        rhs.add_assign(&sy);
        rhs.add_assign(&self.tz);

        rx.revdot(&rhs) == eval(ky.iter(), self.y)
    }
}

/// Verifies some [`Pcd`] for the provided [`Header`].
pub fn verify<C: Cycle, R: Rank, RNG: Rng, H: Header<C::CircuitField>, const HEADER_SIZE: usize>(
    circuit_mesh: &Mesh<'_, C::CircuitField, R>,
    pcd: &Pcd<'_, C, R, H>,
    num_application_steps: usize,
    params: &C,
    mut rng: RNG,
) -> Result<bool> {
    let verifier = Verifier::new(circuit_mesh, num_application_steps, &mut rng);

    // Preamble verification
    let preamble_valid = verifier.check_stage(
        &pcd.proof.preamble.native_preamble_rx,
        internal_circuits::stages::native::preamble::STAGING_ID,
    );

    // Internal circuit c verification
    let c_stage_valid = verifier.check_stage(
        &pcd.proof.internal_circuits.c_rx,
        internal_circuits::c::STAGED_ID,
    );

    let unified_instance = internal_circuits::unified::Instance {
        nested_preamble_commitment: pcd.proof.preamble.nested_preamble_commitment,
        w: pcd.proof.internal_circuits.w,
    };
    let c = internal_circuits::c::Circuit::<C, R>::new(params.circuit_poseidon());
    let unified_ky = c.ky(&unified_instance)?;

    let mut combined_rx = pcd.proof.preamble.native_preamble_rx.clone();
    combined_rx.add_assign(&pcd.proof.internal_circuits.c_rx);

    let c_circuit_valid = verifier.check_internal_circuit(
        &combined_rx,
        internal_circuits::c::CIRCUIT_ID,
        &unified_ky,
    );

    // Application verification
    let left_header =
        FixedVec::<_, ConstLen<HEADER_SIZE>>::try_from(pcd.proof.application.left_header.clone())
            .map_err(|_| Error::MalformedEncoding("left_header has incorrect size".into()))?;
    let right_header =
        FixedVec::<_, ConstLen<HEADER_SIZE>>::try_from(pcd.proof.application.right_header.clone())
            .map_err(|_| Error::MalformedEncoding("right_header has incorrect size".into()))?;

    let application_ky = {
        let adapter = Adapter::<C, StubStep<H>, R, HEADER_SIZE>::new(StubStep::new());
        let instance = (left_header, right_header, pcd.data.clone());
        adapter.ky(instance)?
    };

    let application_valid = verifier.check_circuit(
        &pcd.proof.application.rx,
        pcd.proof.application.circuit_id,
        &application_ky,
    );

    Ok(preamble_valid && c_stage_valid && c_circuit_valid && application_valid)
}
