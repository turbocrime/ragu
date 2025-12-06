use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{
    mesh::Mesh,
    polynomials::{Rank, structured},
};
use ragu_core::maybe::Maybe;

use alloc::{vec, vec::Vec};

use super::{
    header::Header,
    internal_circuits::{self, dummy},
};

/// Represents a recursive proof for the correctness of some computation.
pub struct Proof<C: Cycle, R: Rank> {
    pub(crate) preamble: PreambleProof<C, R>,
    pub(crate) internal_circuits: InternalCircuits<C, R>,
    pub(crate) application: ApplicationProof<C, R>,
}

pub struct ApplicationProof<C: Cycle, R: Rank> {
    pub(crate) circuit_id: usize,
    pub(crate) left_header: Vec<C::CircuitField>,
    pub(crate) right_header: Vec<C::CircuitField>,
    pub(crate) rx: structured::Polynomial<C::CircuitField, R>,
}

pub struct PreambleProof<C: Cycle, R: Rank> {
    pub(crate) native_preamble_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) native_preamble_commitment: C::HostCurve,
    pub(crate) native_preamble_blind: C::CircuitField,
    pub(crate) nested_preamble_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_preamble_commitment: C::NestedCurve,
    pub(crate) nested_preamble_blind: C::ScalarField,
}

pub struct InternalCircuits<C: Cycle, R: Rank> {
    pub(crate) w: C::CircuitField,
    pub(crate) c_rx: structured::Polynomial<C::CircuitField, R>,
}

impl<C: Cycle, R: Rank> Clone for Proof<C, R> {
    fn clone(&self) -> Self {
        Proof {
            preamble: self.preamble.clone(),
            internal_circuits: self.internal_circuits.clone(),
            application: self.application.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Clone for ApplicationProof<C, R> {
    fn clone(&self) -> Self {
        ApplicationProof {
            circuit_id: self.circuit_id,
            left_header: self.left_header.clone(),
            right_header: self.right_header.clone(),
            rx: self.rx.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Clone for PreambleProof<C, R> {
    fn clone(&self) -> Self {
        PreambleProof {
            native_preamble_rx: self.native_preamble_rx.clone(),
            native_preamble_commitment: self.native_preamble_commitment,
            native_preamble_blind: self.native_preamble_blind,
            nested_preamble_rx: self.nested_preamble_rx.clone(),
            nested_preamble_commitment: self.nested_preamble_commitment,
            nested_preamble_blind: self.nested_preamble_blind,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for InternalCircuits<C, R> {
    fn clone(&self) -> Self {
        InternalCircuits {
            w: self.w,
            c_rx: self.c_rx.clone(),
        }
    }
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Augment a recursive proof with some data, described by a [`Header`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data<'_>) -> Pcd<'_, C, R, H> {
        Pcd { proof: self, data }
    }
}

/// Represents proof-carrying data, a recursive proof for the correctness of
/// some accompanying data.
pub struct Pcd<'source, C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    /// The recursive proof for the accompanying data.
    pub proof: Proof<C, R>,

    /// Arbitrary data encoded into a [`Header`].
    pub data: H::Data<'source>,
}

impl<C: Cycle, R: Rank, H: Header<C::CircuitField>> Clone for Pcd<'_, C, R, H> {
    fn clone(&self) -> Self {
        Pcd {
            proof: self.proof.clone(),
            data: self.data.clone(),
        }
    }
}

pub fn trivial<C: Cycle, R: Rank, const HEADER_SIZE: usize>(
    num_application_steps: usize,
    mesh: &Mesh<'_, C::CircuitField, R>,
    params: &C,
) -> Proof<C, R> {
    use internal_circuits::stages;
    use ragu_circuits::{CircuitExt, staging::StageExt};
    use ragu_core::drivers::emulator::Emulator;
    use ragu_primitives::{GadgetExt, Point, Sponge};

    // Preamble rx polynomial
    let native_preamble_rx =
        stages::native::preamble::Stage::<C, R>::rx(()).expect("preamble rx should not fail");
    let native_preamble_blind = C::CircuitField::ONE;
    let native_preamble_commitment =
        native_preamble_rx.commit(params.host_generators(), native_preamble_blind);

    // Nested preamble rx polynomial
    let nested_preamble_rx =
        stages::nested::preamble::Stage::<C::HostCurve, R>::rx(native_preamble_commitment)
            .expect("nested preamble rx should not fail");
    let nested_preamble_blind = C::ScalarField::ONE;
    let nested_preamble_commitment =
        nested_preamble_rx.commit(params.nested_generators(), nested_preamble_blind);

    // Compute w = H(nested_preamble_commitment)
    let circuit_poseidon = params.circuit_poseidon();
    let w: C::CircuitField = Emulator::emulate_wireless(nested_preamble_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        let mut sponge = Sponge::new(dr, circuit_poseidon);
        point.write(dr, &mut sponge)?;
        Ok(*sponge.squeeze(dr)?.value().take())
    })
    .expect("w computation should not fail");

    // Create unified instance and compute c_rx
    let unified_instance = internal_circuits::unified::Instance {
        nested_preamble_commitment,
        w,
    };
    let internal_circuit_c = internal_circuits::c::Circuit::<C, R>::new(circuit_poseidon);
    let internal_circuit_c_witness = internal_circuits::c::Witness {
        unified_instance: &unified_instance,
    };
    let (c_rx, _) = internal_circuit_c
        .rx::<R>(internal_circuit_c_witness, mesh.get_key())
        .expect("c_rx computation should not fail");

    // Application rx polynomial
    let application_rx = dummy::Circuit
        .rx((), mesh.get_key())
        .expect("should not fail")
        .0;

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
            rx: application_rx,
            circuit_id: internal_circuits::index(num_application_steps, dummy::CIRCUIT_ID),
            left_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
            right_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
        },
    }
}
