use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{CircuitExt, mesh::Mesh, polynomials::Rank, staging::StageExt};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{GadgetExt, Point, Sponge};
use rand::Rng;

use crate::{
    internal_circuits,
    proof::{ApplicationProof, InternalCircuits, Pcd, PreambleProof, Proof},
    step::{Step, adapter::Adapter},
};

pub fn merge<'source, C: Cycle, R: Rank, RNG: Rng, S: Step<C>, const HEADER_SIZE: usize>(
    num_application_steps: usize,
    circuit_mesh: &Mesh<'_, C::CircuitField, R>,
    params: &C,
    rng: &mut RNG,
    step: S,
    witness: S::Witness<'source>,
    left: Pcd<'source, C, R, S::Left>,
    right: Pcd<'source, C, R, S::Right>,
) -> Result<(Proof<C, R>, S::Aux<'source>)> {
    let host_generators = params.host_generators();
    let nested_generators = params.nested_generators();
    let circuit_poseidon = params.circuit_poseidon();

    // Compute the preamble (just a stub)
    let native_preamble_rx = internal_circuits::stages::native::preamble::Stage::<C, R>::rx(())?;
    let native_preamble_blind = C::CircuitField::random(&mut *rng);
    let native_preamble_commitment =
        native_preamble_rx.commit(host_generators, native_preamble_blind);

    // Compute nested preamble
    let nested_preamble_rx =
        internal_circuits::stages::nested::preamble::Stage::<C::HostCurve, R>::rx(
            native_preamble_commitment,
        )?;
    let nested_preamble_blind = C::ScalarField::random(&mut *rng);
    let nested_preamble_commitment =
        nested_preamble_rx.commit(nested_generators, nested_preamble_blind);

    // Compute w = H(nested_preamble_commitment)
    let w: C::CircuitField = Emulator::emulate_wireless(nested_preamble_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        let mut sponge = Sponge::new(dr, circuit_poseidon);
        point.write(dr, &mut sponge)?;
        Ok(*sponge.squeeze(dr)?.value().take())
    })?;

    // Create the unified instance.
    let unified_instance = &internal_circuits::unified::Instance {
        nested_preamble_commitment,
        w,
    };

    // Circuit for computing `c` value (incomplete)
    let (c_rx, _) = internal_circuits::c::Circuit::<C, R>::new(circuit_poseidon).rx::<R>(
        internal_circuits::c::Witness { unified_instance },
        circuit_mesh.get_key(),
    )?;

    // Application
    let application_circuit_id = S::INDEX.circuit_index(num_application_steps)?;
    let (application_rx, aux) = Adapter::<C, S, R, HEADER_SIZE>::new(step)
        .rx::<R>((left.data, right.data, witness), circuit_mesh.get_key())?;
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
            internal_circuits: InternalCircuits { w, c_rx },
            application: ApplicationProof {
                circuit_id: application_circuit_id,
                left_header: left_header.into_inner(),
                right_header: right_header.into_inner(),
                rx: application_rx,
            },
        },
        aux,
    ))
}
