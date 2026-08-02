//! Proof corruption utilities for fuzz-testing the verifier.

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
};

use crate::{Application, Proof, framework_hooks::HookConfig};

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
    /// Perturb the claimed evaluation `y` of the poly-query claim in the given slot.
    ClaimY(usize, F),
    /// Perturb the first coordinate of the given claim slot's name so it matches no slot.
    ClaimName(usize, F),
    /// Perturb one coordinate instance wire, leaving the recorded hosts and the
    /// claim polynomials untouched.
    ApplicationCoord(usize, F),
    /// Perturb the derived challenge in the given slot (the challenge-grinding shape).
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
            Corruption::ApplicationCoord(index, v) => {
                self.application_poly_coords[index] += v;
            }
            Corruption::ChallengeValue(slot, v) => {
                self.application_challenges[slot].challenge += v;
            }
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig>
    Application<'_, C, R, HEADER_SIZE, J>
{
    /// Create a trivial (all-zero) proof for testing.
    pub fn test_trivial_proof(&self) -> Proof<C, R> {
        self.trivial_proof()
    }
}
