//! Evaluate $p(X)$.
//!
//! This creates the [`proof::P`] component of the proof, which contains the
//! accumulated polynomial $p(X)$ and its claimed evaluation $p(u) = v$.

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::Element;
use rand::Rng;

use crate::{Application, Proof, proof};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_p<'dr, D, RNG: Rng>(
        &self,
        rng: &mut RNG,
        beta: &Element<'dr, D>,
        u: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &proof::SPrime<C, R>,
        error_m: &proof::ErrorM<C, R>,
        ab: &proof::AB<C, R>,
        query: &proof::Query<C, R>,
        f: &proof::F<C, R>,
    ) -> Result<proof::P<C, R>>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        let mut poly = f.poly.clone();

        // The orderings in this code must match the corresponding struct
        // definition ordering of `stages::native::eval::Output`.
        {
            let beta = *beta.value().take();
            let acc_s = |p: &mut ragu_circuits::polynomials::unstructured::Polynomial<_, _>,
                         term| {
                p.scale(beta);
                p.add_structured(term);
            };
            let acc_u = |p: &mut ragu_circuits::polynomials::unstructured::Polynomial<_, _>,
                         term| {
                p.scale(beta);
                p.add_assign(term);
            };

            for proof in [left, right] {
                acc_s(&mut poly, &proof.application.rx);
                acc_s(&mut poly, &proof.preamble.stage_rx);
                acc_s(&mut poly, &proof.error_n.stage_rx);
                acc_s(&mut poly, &proof.error_m.stage_rx);
                acc_s(&mut poly, &proof.ab.a_poly);
                acc_s(&mut poly, &proof.ab.b_poly);
                acc_s(&mut poly, &proof.query.stage_rx);
                acc_u(&mut poly, &proof.query.mesh_xy_poly);
                acc_s(&mut poly, &proof.eval.stage_rx);
                acc_u(&mut poly, &proof.p.poly);
                acc_s(&mut poly, &proof.circuits.hashes_1_rx);
                acc_s(&mut poly, &proof.circuits.hashes_2_rx);
                acc_s(&mut poly, &proof.circuits.partial_collapse_rx);
                acc_s(&mut poly, &proof.circuits.full_collapse_rx);
                acc_s(&mut poly, &proof.circuits.compute_v_rx);
            }

            acc_u(&mut poly, &s_prime.mesh_wx0_poly);
            acc_u(&mut poly, &s_prime.mesh_wx1_poly);
            acc_s(&mut poly, &error_m.mesh_wy_poly);
            acc_s(&mut poly, &ab.a_poly);
            acc_s(&mut poly, &ab.b_poly);
            acc_u(&mut poly, &query.mesh_xy_poly);
        }

        let blind = C::CircuitField::random(&mut *rng);
        let commitment = poly.commit(C::host_generators(self.params), blind);

        let v = poly.eval(*u.value().take());

        Ok(proof::P {
            poly,
            blind,
            commitment,
            v,
        })
    }
}
