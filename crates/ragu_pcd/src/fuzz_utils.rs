//! Proof corruption utilities for fuzz-testing the verifier.

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};

use crate::{AppHooksLayout, Application, Proof};

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
    /// Perturb the first coordinate of the given claim slot's **name** — the
    /// opened polynomial's embedded host coordinates — leaving the poly
    /// region and everything else untouched, so the name matches no slot.
    /// The root verifier's claim walk resolves it to nothing; a parent's
    /// `_08_f` finds no polynomial for the quotient and `compute_v`'s one-hot
    /// cannot select.
    ClaimName(usize, F),
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
            Corruption::ClaimName(slot, v) => {
                self.application_claims[slot].coords[0] += v;
            }
            Corruption::ChallengeValue(slot, v) => {
                self.application_challenges[slot].challenge += v;
            }
        }
    }
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Replaces one coordinate instance wire's recorded value, leaving
    /// everything else — the recorded hosts and the claim polynomials —
    /// untouched.
    ///
    /// Models a prover whose step used a representation that is not the
    /// recorded host's. Exactly two checks are supposed to reject it: at
    /// root, `verify` recomputes every slot's coordinates from the recorded
    /// host; fused as a child, the parent's `compute_v` re-derives the
    /// claim-coordinate polynomial's $q(u)$ from these wires and enforces it
    /// against the eval stage's carried value.
    pub fn corrupt_application_coord(&mut self, index: usize, value: C::CircuitField) {
        self.application_poly_coords[index] = value;
    }

    /// The instance-bound opening $(x, y)$ this proof claims in `slot`.
    ///
    /// Exists for one job: letting a test establish *what* a proof claims
    /// before asserting how the verifier treats it, so a rejection can be
    /// attributed to the desync under test. Behind this feature because a
    /// consumer's contract with a proof is
    /// [`Application::verify`](crate::Application::verify), which checks the
    /// slot lists itself.
    pub fn claim_opening_for_testing(&self, slot: usize) -> (C::CircuitField, C::CircuitField) {
        let claim = &self.application_claims[slot];
        (claim.x, claim.y)
    }
}

impl<C: Cycle, R: Rank, H: crate::Header<C::CircuitField>> crate::Pcd<C, R, H> {
    /// Apply a [`Corruption`] to the underlying proof.
    pub fn corrupt(&mut self, corruption: Corruption<C::CircuitField>) {
        self.proof_mut().corrupt(corruption);
    }

    /// Apply [`Proof::corrupt_application_coord`] to the underlying proof.
    pub fn corrupt_application_coord(&mut self, index: usize, value: C::CircuitField) {
        self.proof_mut().corrupt_application_coord(index, value);
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, J: AppHooksLayout>
    Application<'_, C, R, HEADER_SIZE, J>
{
    /// Create a trivial (all-zero) proof for testing.
    pub fn test_trivial_proof(&self) -> Proof<C, R> {
        self.trivial_proof()
    }
}
