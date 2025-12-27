use arithmetic::{Cycle, FixedGenerators};
use ff::Field;
use ragu_circuits::{
    CircuitExt,
    mesh::CircuitIndex,
    polynomials::{Rank, structured, unstructured},
};

use alloc::vec;
use alloc::vec::Vec;

use crate::{Application, header::Header, internal_circuits::dummy};

/// Represents a recursive proof for the correctness of some computation.
pub struct Proof<C: Cycle, R: Rank> {
    pub(crate) application: ApplicationProof<C, R>,
    pub(crate) preamble: PreambleProof<C, R>,
    pub(crate) s_prime: SPrimeProof<C, R>,
    pub(crate) error_m: ErrorMProof<C, R>,
    pub(crate) error_n: ErrorNProof<C, R>,
    pub(crate) ab: ABProof<C, R>,
    pub(crate) query: QueryProof<C, R>,
    pub(crate) f: FProof<C, R>,
    pub(crate) eval: EvalProof<C, R>,
    pub(crate) challenges: Challenges<C>,
    pub(crate) circuits: CircuitCommitments<C, R>,
}

/// Application-specific proof data including circuit ID, headers, and commitment.
pub(crate) struct ApplicationProof<C: Cycle, R: Rank> {
    pub(crate) circuit_id: CircuitIndex,
    pub(crate) left_header: Vec<C::CircuitField>,
    pub(crate) right_header: Vec<C::CircuitField>,
    pub(crate) rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) blind: C::CircuitField,
    pub(crate) commitment: C::HostCurve,
}

/// Preamble stage proof with native and nested layer commitments.
pub(crate) struct PreambleProof<C: Cycle, R: Rank> {
    pub(crate) stage_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) stage_blind: C::CircuitField,
    /// This can be computed using stage_rx / stage_blind
    pub(crate) stage_commitment: C::HostCurve,

    /// This can be computed using stage_commitment
    pub(crate) nested_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_blind: C::ScalarField,
    /// This can be computed using nested_rx / nested_blind
    pub(crate) nested_commitment: C::NestedCurve,
}

/// S' stage proof: m(w, x_i, Y) and nested commitment.
pub(crate) struct SPrimeProof<C: Cycle, R: Rank> {
    pub(crate) mesh_wx0_poly: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) mesh_wx0_blind: C::CircuitField,
    pub(crate) mesh_wx0_commitment: C::HostCurve,

    pub(crate) mesh_wx1_poly: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) mesh_wx1_blind: C::CircuitField,
    pub(crate) mesh_wx1_commitment: C::HostCurve,

    pub(crate) nested_s_prime_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_s_prime_blind: C::ScalarField,
    pub(crate) nested_s_prime_commitment: C::NestedCurve,
}

/// Error M stage proof with mesh_wy bundled (Layer 1: N instances of M-sized reductions).
pub(crate) struct ErrorMProof<C: Cycle, R: Rank> {
    // Mesh m(w, X, y) components
    pub(crate) mesh_wy_poly: structured::Polynomial<C::CircuitField, R>,
    pub(crate) mesh_wy_blind: C::CircuitField,
    pub(crate) mesh_wy_commitment: C::HostCurve,

    // Error M stage components
    pub(crate) stage_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) stage_blind: C::CircuitField,
    pub(crate) stage_commitment: C::HostCurve,

    // Nested layer (bundles mesh_wy_commitment + stage_commitment)
    pub(crate) nested_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_blind: C::ScalarField,
    pub(crate) nested_commitment: C::NestedCurve,
}

/// Error N stage proof (Layer 2: Single N-sized reduction).
pub(crate) struct ErrorNProof<C: Cycle, R: Rank> {
    pub(crate) stage_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) stage_blind: C::CircuitField,
    pub(crate) stage_commitment: C::HostCurve,
    pub(crate) nested_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_blind: C::ScalarField,
    pub(crate) nested_commitment: C::NestedCurve,
}

/// A/B polynomial proof for folding. A and B depend on (mu, nu).
pub(crate) struct ABProof<C: Cycle, R: Rank> {
    pub(crate) a_poly: structured::Polynomial<C::CircuitField, R>,
    pub(crate) a_blind: C::CircuitField,
    pub(crate) a_commitment: C::HostCurve,

    pub(crate) b_poly: structured::Polynomial<C::CircuitField, R>,
    pub(crate) b_blind: C::CircuitField,
    pub(crate) b_commitment: C::HostCurve,

    pub(crate) nested_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_blind: C::ScalarField,
    pub(crate) nested_commitment: C::NestedCurve,
}

/// Query stage proof with mesh_xy bundled.
pub(crate) struct QueryProof<C: Cycle, R: Rank> {
    // Mesh m(x, y) components
    pub(crate) mesh_xy_poly: unstructured::Polynomial<C::CircuitField, R>,
    pub(crate) mesh_xy_blind: C::CircuitField,
    pub(crate) mesh_xy_commitment: C::HostCurve,

    // Query stage components
    pub(crate) stage_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) stage_blind: C::CircuitField,
    pub(crate) stage_commitment: C::HostCurve,

    // Nested layer (bundles mesh_xy_commitment + stage_commitment)
    pub(crate) nested_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_blind: C::ScalarField,
    pub(crate) nested_commitment: C::NestedCurve,
}

/// F polynomial proof with native and nested layer commitments.
pub(crate) struct FProof<C: Cycle, R: Rank> {
    pub(crate) poly: structured::Polynomial<C::CircuitField, R>,
    pub(crate) blind: C::CircuitField,
    pub(crate) commitment: C::HostCurve,

    pub(crate) nested_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_blind: C::ScalarField,
    pub(crate) nested_commitment: C::NestedCurve,
}

/// Evaluation stage proof with native and nested layer commitments.
pub(crate) struct EvalProof<C: Cycle, R: Rank> {
    pub(crate) stage_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) stage_blind: C::CircuitField,
    pub(crate) stage_commitment: C::HostCurve,

    pub(crate) nested_rx: structured::Polynomial<C::ScalarField, R>,
    pub(crate) nested_blind: C::ScalarField,
    pub(crate) nested_commitment: C::NestedCurve,
}

/// Fiat-Shamir challenges derived during proof generation.
pub(crate) struct Challenges<C: Cycle> {
    pub(crate) w: C::CircuitField,
    pub(crate) y: C::CircuitField,
    pub(crate) z: C::CircuitField,
    pub(crate) mu: C::CircuitField,
    pub(crate) nu: C::CircuitField,
    pub(crate) mu_prime: C::CircuitField,
    pub(crate) nu_prime: C::CircuitField,
    pub(crate) c: C::CircuitField,
    pub(crate) x: C::CircuitField,
    pub(crate) alpha: C::CircuitField,
    pub(crate) u: C::CircuitField,
    pub(crate) beta: C::CircuitField,
}

/// Circuit polynomial commitments (C, V, hashes, ky).
pub(crate) struct CircuitCommitments<C: Cycle, R: Rank> {
    pub(crate) c_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) c_blind: C::CircuitField,
    pub(crate) c_commitment: C::HostCurve,
    pub(crate) v_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) v_blind: C::CircuitField,
    pub(crate) v_commitment: C::HostCurve,
    pub(crate) hashes_1_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) hashes_1_blind: C::CircuitField,
    pub(crate) hashes_1_commitment: C::HostCurve,
    pub(crate) hashes_2_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) hashes_2_blind: C::CircuitField,
    pub(crate) hashes_2_commitment: C::HostCurve,
    pub(crate) ky_rx: structured::Polynomial<C::CircuitField, R>,
    pub(crate) ky_blind: C::CircuitField,
    pub(crate) ky_commitment: C::HostCurve,
}

impl<C: Cycle, R: Rank> Clone for Proof<C, R> {
    fn clone(&self) -> Self {
        Proof {
            application: self.application.clone(),
            preamble: self.preamble.clone(),
            s_prime: self.s_prime.clone(),
            error_m: self.error_m.clone(),
            error_n: self.error_n.clone(),
            ab: self.ab.clone(),
            query: self.query.clone(),
            f: self.f.clone(),
            eval: self.eval.clone(),
            challenges: self.challenges.clone(),
            circuits: self.circuits.clone(),
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
            blind: self.blind,
            commitment: self.commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for PreambleProof<C, R> {
    fn clone(&self) -> Self {
        PreambleProof {
            stage_rx: self.stage_rx.clone(),
            stage_blind: self.stage_blind,
            stage_commitment: self.stage_commitment,
            nested_rx: self.nested_rx.clone(),
            nested_blind: self.nested_blind,
            nested_commitment: self.nested_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for SPrimeProof<C, R> {
    fn clone(&self) -> Self {
        SPrimeProof {
            mesh_wx0_poly: self.mesh_wx0_poly.clone(),
            mesh_wx0_blind: self.mesh_wx0_blind,
            mesh_wx0_commitment: self.mesh_wx0_commitment,
            mesh_wx1_poly: self.mesh_wx1_poly.clone(),
            mesh_wx1_blind: self.mesh_wx1_blind,
            mesh_wx1_commitment: self.mesh_wx1_commitment,
            nested_s_prime_rx: self.nested_s_prime_rx.clone(),
            nested_s_prime_blind: self.nested_s_prime_blind,
            nested_s_prime_commitment: self.nested_s_prime_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for ErrorMProof<C, R> {
    fn clone(&self) -> Self {
        ErrorMProof {
            mesh_wy_poly: self.mesh_wy_poly.clone(),
            mesh_wy_blind: self.mesh_wy_blind,
            mesh_wy_commitment: self.mesh_wy_commitment,
            stage_rx: self.stage_rx.clone(),
            stage_blind: self.stage_blind,
            stage_commitment: self.stage_commitment,
            nested_rx: self.nested_rx.clone(),
            nested_blind: self.nested_blind,
            nested_commitment: self.nested_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for ErrorNProof<C, R> {
    fn clone(&self) -> Self {
        ErrorNProof {
            stage_rx: self.stage_rx.clone(),
            stage_blind: self.stage_blind,
            stage_commitment: self.stage_commitment,
            nested_rx: self.nested_rx.clone(),
            nested_blind: self.nested_blind,
            nested_commitment: self.nested_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for ABProof<C, R> {
    fn clone(&self) -> Self {
        ABProof {
            a_poly: self.a_poly.clone(),
            a_blind: self.a_blind,
            a_commitment: self.a_commitment,
            b_poly: self.b_poly.clone(),
            b_blind: self.b_blind,
            b_commitment: self.b_commitment,
            nested_rx: self.nested_rx.clone(),
            nested_blind: self.nested_blind,
            nested_commitment: self.nested_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for QueryProof<C, R> {
    fn clone(&self) -> Self {
        QueryProof {
            mesh_xy_poly: self.mesh_xy_poly.clone(),
            mesh_xy_blind: self.mesh_xy_blind,
            mesh_xy_commitment: self.mesh_xy_commitment,
            stage_rx: self.stage_rx.clone(),
            stage_blind: self.stage_blind,
            stage_commitment: self.stage_commitment,
            nested_rx: self.nested_rx.clone(),
            nested_blind: self.nested_blind,
            nested_commitment: self.nested_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for FProof<C, R> {
    fn clone(&self) -> Self {
        FProof {
            poly: self.poly.clone(),
            blind: self.blind,
            commitment: self.commitment,
            nested_rx: self.nested_rx.clone(),
            nested_blind: self.nested_blind,
            nested_commitment: self.nested_commitment,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for EvalProof<C, R> {
    fn clone(&self) -> Self {
        EvalProof {
            stage_rx: self.stage_rx.clone(),
            stage_blind: self.stage_blind,
            stage_commitment: self.stage_commitment,
            nested_rx: self.nested_rx.clone(),
            nested_blind: self.nested_blind,
            nested_commitment: self.nested_commitment,
        }
    }
}

impl<C: Cycle> Clone for Challenges<C> {
    fn clone(&self) -> Self {
        Challenges {
            w: self.w,
            y: self.y,
            z: self.z,
            mu: self.mu,
            nu: self.nu,
            mu_prime: self.mu_prime,
            nu_prime: self.nu_prime,
            c: self.c,
            x: self.x,
            alpha: self.alpha,
            u: self.u,
            beta: self.beta,
        }
    }
}

impl<C: Cycle, R: Rank> Clone for CircuitCommitments<C, R> {
    fn clone(&self) -> Self {
        CircuitCommitments {
            c_rx: self.c_rx.clone(),
            c_blind: self.c_blind,
            c_commitment: self.c_commitment,
            v_rx: self.v_rx.clone(),
            v_blind: self.v_blind,
            v_commitment: self.v_commitment,
            hashes_1_rx: self.hashes_1_rx.clone(),
            hashes_1_blind: self.hashes_1_blind,
            hashes_1_commitment: self.hashes_1_commitment,
            hashes_2_rx: self.hashes_2_rx.clone(),
            hashes_2_blind: self.hashes_2_blind,
            hashes_2_commitment: self.hashes_2_commitment,
            ky_rx: self.ky_rx.clone(),
            ky_blind: self.ky_blind,
            ky_commitment: self.ky_commitment,
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

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Creates a minimal trivial proof wrapped as a PCD with empty header.
    /// Used internally for rerandomization.
    pub(crate) fn trivial_pcd<'source>(&self) -> Pcd<'source, C, R, ()> {
        self.trivial_proof().carry(())
    }

    /// Creates a trivial proof for the empty [`Header`] implementation `()`.
    ///
    /// Trivial proofs use zero polynomials and deterministic blindings. They
    /// are not meant to verify on their own, but are used as inputs to `fuse`
    /// to produce valid proofs.
    ///
    /// See also: `seed()` for the public API to seed new computations.
    pub(crate) fn trivial_proof(&self) -> Proof<C, R> {
        // Deterministic blindings
        let host_blind = C::CircuitField::ONE;
        let nested_blind = C::ScalarField::ONE;

        // Generator points
        let host_g = self.params.host_generators().g()[0];
        let nested_g = self.params.nested_generators().g()[0];

        // Zero polynomials
        let zero_structured_host = structured::Polynomial::<C::CircuitField, R>::new();
        let zero_structured_nested = structured::Polynomial::<C::ScalarField, R>::new();
        let zero_unstructured = unstructured::Polynomial::<C::CircuitField, R>::new();

        // Dummy circuit rx for application field
        let dummy_rx = dummy::Circuit
            .rx((), self.circuit_mesh.get_key())
            .expect("dummy circuit rx should not fail")
            .0;
        let dummy_commitment = dummy_rx.commit(self.params.host_generators(), host_blind);
        let dummy_circuit_id = dummy::CIRCUIT_ID.circuit_index(self.num_application_steps);

        Proof {
            application: ApplicationProof {
                circuit_id: dummy_circuit_id,
                left_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                right_header: vec![C::CircuitField::ZERO; HEADER_SIZE],
                rx: dummy_rx.clone(),
                blind: host_blind,
                commitment: dummy_commitment,
            },
            preamble: PreambleProof {
                stage_rx: zero_structured_host.clone(),
                stage_blind: host_blind,
                stage_commitment: host_g,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment: nested_g,
            },
            s_prime: SPrimeProof {
                mesh_wx0_poly: zero_unstructured.clone(),
                mesh_wx0_blind: host_blind,
                mesh_wx0_commitment: host_g,
                mesh_wx1_poly: zero_unstructured.clone(),
                mesh_wx1_blind: host_blind,
                mesh_wx1_commitment: host_g,
                nested_s_prime_rx: zero_structured_nested.clone(),
                nested_s_prime_blind: nested_blind,
                nested_s_prime_commitment: nested_g,
            },
            error_m: ErrorMProof {
                mesh_wy_poly: zero_structured_host.clone(),
                mesh_wy_blind: host_blind,
                mesh_wy_commitment: host_g,
                stage_rx: zero_structured_host.clone(),
                stage_blind: host_blind,
                stage_commitment: host_g,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment: nested_g,
            },
            error_n: ErrorNProof {
                stage_rx: zero_structured_host.clone(),
                stage_blind: host_blind,
                stage_commitment: host_g,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment: nested_g,
            },
            ab: ABProof {
                a_poly: zero_structured_host.clone(),
                a_blind: host_blind,
                a_commitment: host_g,
                b_poly: zero_structured_host.clone(),
                b_blind: host_blind,
                b_commitment: host_g,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment: nested_g,
            },
            query: QueryProof {
                mesh_xy_poly: zero_unstructured.clone(),
                mesh_xy_blind: host_blind,
                mesh_xy_commitment: host_g,
                stage_rx: zero_structured_host.clone(),
                stage_blind: host_blind,
                stage_commitment: host_g,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment: nested_g,
            },
            f: FProof {
                poly: zero_structured_host.clone(),
                blind: host_blind,
                commitment: host_g,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment: nested_g,
            },
            eval: EvalProof {
                stage_rx: zero_structured_host.clone(),
                stage_blind: host_blind,
                stage_commitment: host_g,
                nested_rx: zero_structured_nested.clone(),
                nested_blind,
                nested_commitment: nested_g,
            },
            challenges: Challenges {
                w: C::CircuitField::ZERO,
                y: C::CircuitField::ZERO,
                z: C::CircuitField::ZERO,
                mu: C::CircuitField::ZERO,
                nu: C::CircuitField::ZERO,
                mu_prime: C::CircuitField::ZERO,
                nu_prime: C::CircuitField::ZERO,
                c: C::CircuitField::ZERO,
                x: C::CircuitField::ZERO,
                alpha: C::CircuitField::ZERO,
                u: C::CircuitField::ZERO,
                beta: C::CircuitField::ZERO,
            },
            circuits: CircuitCommitments {
                c_rx: dummy_rx.clone(),
                c_blind: host_blind,
                c_commitment: dummy_commitment,
                v_rx: dummy_rx.clone(),
                v_blind: host_blind,
                v_commitment: dummy_commitment,
                hashes_1_rx: dummy_rx.clone(),
                hashes_1_blind: host_blind,
                hashes_1_commitment: dummy_commitment,
                hashes_2_rx: dummy_rx.clone(),
                hashes_2_blind: host_blind,
                hashes_2_commitment: dummy_commitment,
                ky_rx: dummy_rx.clone(),
                ky_blind: host_blind,
                ky_commitment: dummy_commitment,
            },
        }
    }
}
