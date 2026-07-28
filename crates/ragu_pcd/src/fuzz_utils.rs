//! Proof corruption utilities for fuzz-testing the verifier.

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};

use crate::{Application, Proof};

/// Targeted corruption of a single proof field.
///
/// Each variant breaks a specific verification check.
pub enum Corruption<F> {
    /// Perturb `native_p_poly` at coefficient 0, breaking the P commitment check.
    PBlind(F),
    /// Perturb `native_p_poly` at coefficient 1, breaking the P evaluation check.
    PEval(F),
    /// Perturb `native_a_poly` at coefficient 0, breaking native revdot claims.
    AbC(F),
    /// Set `circuit_id` to an out-of-domain index.
    CircuitId(u32),
    /// Overwrite challenge `u`, breaking the P evaluation check.
    ChallengeU(F),
    /// Overwrite challenge `x`, breaking the registry xy check.
    ChallengeX(F),
    /// Overwrite challenge `y`, breaking the registry xy check.
    ChallengeY(F),
    /// Resize `left_header` to the given length.
    LeftHeaderLen(usize),
    /// Resize `right_header` to the given length.
    RightHeaderLen(usize),
    /// Perturb the claimed evaluation `y` of the poly-query claim in the
    /// given slot, breaking the claim's evaluation binding. The root verifier
    /// rejects the proof directly; a parent fuse's circuits reject it
    /// recursively (the instance-bound claim no longer matches the
    /// application circuit's k(Y), and `compute_v`'s claim quotient breaks).
    ClaimY(usize, F),
    /// Perturb the derived challenge in the given slot, leaving the point it
    /// was derived from intact. This is the challenge-grinding shape: a prover
    /// who wants a challenge other than the one its committed inputs hash to.
    /// The `challenge_binding` circuit re-derives $\text{Hash}(\text{point})$
    /// for every child slot, so a parent cannot assemble its trace at all.
    ChallengeValue(usize, F),
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Apply a [`Corruption`] to this proof.
    pub fn corrupt(&mut self, corruption: Corruption<C::CircuitField>) {
        match corruption {
            Corruption::PBlind(v) => self
                .native_p_poly
                .add_assign(&sparse::Polynomial::from_coeffs(alloc::vec![v])),
            Corruption::PEval(v) => {
                self.native_p_poly
                    .add_assign(&sparse::Polynomial::from_coeffs(alloc::vec![
                        C::CircuitField::ZERO,
                        v,
                    ]))
            }
            Corruption::AbC(v) => self
                .native_a_poly
                .add_assign(&sparse::Polynomial::from_coeffs(alloc::vec![v])),
            Corruption::CircuitId(id) => {
                self.circuit_id = CircuitIndex::from_u32(id);
            }
            Corruption::ChallengeU(v) => self.u = v,
            Corruption::ChallengeX(v) => self.x = v,
            Corruption::ChallengeY(v) => self.y = v,
            Corruption::LeftHeaderLen(len) => {
                self.left_header.resize(len, C::CircuitField::ZERO);
            }
            Corruption::RightHeaderLen(len) => {
                self.right_header.resize(len, C::CircuitField::ZERO);
            }
            Corruption::ClaimY(slot, v) => {
                self.application_claims[slot].y += v;
            }
            Corruption::ChallengeValue(slot, v) => {
                self.application_challenges[slot].challenge += v;
            }
        }
    }
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Replace the carried claim polynomial and its host commitment in `slot`,
    /// leaving the instance-bound claim `(com, x, y)` — and therefore the
    /// application circuit's $k(Y)$ binding — untouched.
    ///
    /// This is the *poly-query commitment binding* attack shape: a prover
    /// declares a claim against `com` (which the step's Fiat–Shamir challenges
    /// and header hashes reference) but hands the parent a different
    /// polynomial to fold. Passing a `poly` that still satisfies
    /// `poly.eval(x) == y` keeps the parent's $f(X)$ quotient exact, so the
    /// fuse has no honest reason to reject.
    ///
    /// `host` should be `poly`'s host-curve commitment, so the substitution is
    /// self-consistent everywhere the *host* side is checked.
    pub fn corrupt_claim_poly(
        &mut self,
        slot: usize,
        poly: sparse::Polynomial<C::CircuitField, R>,
        host: C::HostCurve,
    ) {
        self.claim_polys[slot] = poly;
        self.set_claim_host_commitment(slot, host);
    }
}

impl<C: Cycle, R: Rank, H: crate::Header<C::CircuitField>> crate::Pcd<C, R, H> {
    /// Apply a [`Corruption`] to the underlying proof.
    pub fn corrupt(&mut self, corruption: Corruption<C::CircuitField>) {
        self.proof_mut().corrupt(corruption);
    }

    /// Apply [`Proof::corrupt_claim_poly`] to the underlying proof.
    pub fn corrupt_claim_poly(
        &mut self,
        slot: usize,
        poly: sparse::Polynomial<C::CircuitField, R>,
        host: C::HostCurve,
    ) {
        self.proof_mut().corrupt_claim_poly(slot, poly, host);
    }
}

impl<
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
> Application<'_, C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>
{
    /// Create a trivial (all-zero) proof for testing.
    pub fn test_trivial_proof(&self) -> Proof<C, R> {
        self.trivial_proof()
    }
}
