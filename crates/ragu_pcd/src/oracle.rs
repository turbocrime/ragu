//! Sound in-circuit polynomial oracle.
//!
//! [`WitnessedPolynomial`] witnesses a polynomial's coefficients *in-circuit*
//! so that everything derived from it is enforced by the application circuit —
//! and therefore inherits the proof system's soundness — with no native
//! side-channels:
//!
//! * [`eval`](WitnessedPolynomial::eval) evaluates at any in-circuit point via
//!   Horner's rule; the returned element is *constrained* to be the
//!   evaluation, so using it (or [`enforce_equal`] against a claimed value)
//!   soundly enforces the evaluation claim.
//! * [`hash_commitment`](WitnessedPolynomial::hash_commitment) produces a
//!   Poseidon binding commitment to the coefficients as a single [`Element`],
//!   suitable for exposing through a [`Header`](crate::header::Header) so the
//!   *same* polynomial is provably threaded between PCD nodes: a child
//!   re-witnesses the coefficients and equates the recomputed hash with the
//!   header's element.
//! * A [`WitnessedPolynomial`] is a [`ChallengeInput`], so a Fiat–Shamir
//!   challenge from [`StepCtx::derive_challenge`] can be bound directly to the
//!   full coefficient vector (or to its hash commitment, for a cheaper
//!   sponge).
//!
//! Together with [`StepCtx::derive_challenge`], this covers the full oracle
//! loop soundly today: witness a polynomial, derive a challenge, evaluate at
//! it, and enforce the evaluation. The price is that the polynomial lives in
//! the circuit (one wire per coefficient up to the declared capacity, plus
//! one multiply-add per coefficient for each evaluation). For polynomials too
//! large for that price, the *succinct* path —
//! [`StepCtx::enforce_poly_query`], where the polynomial stays outside the
//! circuit and only the claim `(com, x, y)` is recorded — is pre-checked
//! natively at the fuse that raises it, then enforced recursively at the next
//! fuse by folding into the proof system's $(P, u, v)$ accumulator, at parity
//! with the framework's own $f$/$p$/bridge components. (The accumulator's
//! final root opening by the verifier is a pre-existing framework-wide
//! follow-up tracked on `main`, not specific to poly-query claims.)
//!
//! ## Capacity
//!
//! Circuit structure must be witness-independent, so a `WitnessedPolynomial`
//! is allocated with a fixed `capacity`: shorter coefficient vectors are
//! zero-padded, longer ones are rejected as an invalid witness. All
//! structural quantities (wire count, evaluation cost, hash width) depend
//! only on `capacity`.
//!
//! [`enforce_equal`]: ragu_primitives::GadgetExt::enforce_equal
//! [`StepCtx::derive_challenge`]: crate::step::StepCtx::derive_challenge
//! [`StepCtx::enforce_poly_query`]: crate::step::StepCtx::enforce_poly_query

use alloc::vec::Vec;

use ragu_arithmetic::{PoseidonPermutation, ff::Field};
use ragu_circuits::horner::Horner;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, allocator::Standard, poseidon::Sponge};

use crate::framework_hooks::ChallengeInput;

/// A polynomial witnessed in-circuit: one [`Element`] per coefficient
/// (little-endian, zero-padded to the declared capacity). See the
/// [module docs](self).
pub struct WitnessedPolynomial<'dr, D: Driver<'dr>> {
    /// Coefficient elements, little-endian; `coefficients.len()` is the
    /// declared capacity.
    coefficients: Vec<Element<'dr, D>>,
}

impl<'dr, D: Driver<'dr>> WitnessedPolynomial<'dr, D> {
    /// Allocates a polynomial with the given `capacity` from its little-endian
    /// `coefficients`. Shorter vectors are zero-padded; longer vectors are
    /// rejected with [`Error::InvalidWitness`] on value-carrying drivers.
    pub fn alloc(
        dr: &mut D,
        capacity: usize,
        coefficients: DriverValue<D, Vec<D::F>>,
    ) -> Result<Self> {
        let checked: DriverValue<D, Vec<D::F>> = D::try_just(|| {
            let coefficients = coefficients.take();
            if coefficients.len() > capacity {
                return Err(Error::InvalidWitness(
                    "polynomial coefficient count exceeds the witnessed capacity".into(),
                ));
            }
            Ok(coefficients)
        })?;

        let allocator = &mut Standard::new();
        let mut elements = Vec::with_capacity(capacity);
        for i in 0..capacity {
            let coeff = checked
                .as_ref()
                .map(|c| c.get(i).copied().unwrap_or(D::F::ZERO));
            elements.push(Element::alloc(dr, allocator, coeff)?);
        }
        Ok(Self {
            coefficients: elements,
        })
    }

    /// The declared capacity (coefficient count including zero padding).
    pub fn capacity(&self) -> usize {
        self.coefficients.len()
    }

    /// The coefficient elements, little-endian, including zero padding.
    pub fn coefficients(&self) -> &[Element<'dr, D>] {
        &self.coefficients
    }

    /// Evaluates the polynomial at `z` via Horner's rule. The returned
    /// element is constrained to be the evaluation, so it can be used
    /// directly — or equated with a claimed value via
    /// [`enforce_equal`](ragu_primitives::GadgetExt::enforce_equal) — to
    /// soundly enforce an evaluation claim.
    pub fn eval(&self, dr: &mut D, z: &Element<'dr, D>) -> Result<Element<'dr, D>> {
        let mut horner = Horner::new(z);
        for coefficient in self.coefficients.iter().rev() {
            coefficient.write(dr, &mut horner)?;
        }
        Ok(horner.finish(dr))
    }

    /// Hashes the coefficients into a single binding commitment element with
    /// the given Poseidon parameters. Two polynomials of the same capacity
    /// hash equal iff their coefficients are equal (up to hash collisions),
    /// so exposing this element through a header soundly threads the
    /// polynomial between PCD nodes.
    pub fn hash_commitment<P: PoseidonPermutation<D::F>>(
        &self,
        dr: &mut D,
        poseidon: &'dr P,
    ) -> Result<Element<'dr, D>> {
        let mut sponge = Sponge::new(dr, poseidon);
        for coefficient in &self.coefficients {
            sponge.absorb(dr, coefficient)?;
        }
        sponge.squeeze(dr)
    }
}

impl<'dr, D: Driver<'dr>> ChallengeInput<'dr, D> for WitnessedPolynomial<'dr, D> {
    fn append_elements(&self, _dr: &mut D, out: &mut Vec<Element<'dr, D>>) -> Result<()> {
        out.extend(self.coefficients.iter().cloned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::Cycle;
    use ragu_core::{
        drivers::emulator::Emulator,
        maybe::{Always, Maybe as _, MaybeKind},
    };
    use ragu_pasta::{Fp, Pasta};

    use super::*;

    fn coeffs(values: &[u64]) -> Vec<Fp> {
        values.iter().map(|v| Fp::from(*v)).collect()
    }

    /// `eval` matches native Horner evaluation, including zero padding.
    #[test]
    fn eval_matches_native() {
        let mut dr = Emulator::execute();
        let poly =
            WitnessedPolynomial::alloc(&mut dr, 8, Always::maybe_just(|| coeffs(&[3, 1, 4, 1, 5])))
                .expect("alloc");
        assert_eq!(poly.capacity(), 8);

        let z = Element::alloc(
            &mut dr,
            &mut Standard::new(),
            Always::maybe_just(|| Fp::from(9u64)),
        )
        .expect("alloc z");
        let y = poly.eval(&mut dr, &z).expect("eval");

        let expected = ragu_arithmetic::eval(&coeffs(&[3, 1, 4, 1, 5]), Fp::from(9u64));
        assert_eq!(*y.value().take(), expected);
    }

    /// Oversized coefficient vectors are rejected.
    #[test]
    fn oversized_witness_is_rejected() {
        let mut dr = Emulator::execute();
        let result =
            WitnessedPolynomial::alloc(&mut dr, 2, Always::maybe_just(|| coeffs(&[1, 2, 3])));
        assert!(matches!(result, Err(Error::InvalidWitness(_))));
    }

    /// The hash commitment is deterministic and binding on the coefficients.
    #[test]
    fn hash_commitment_binds_coefficients() {
        let pasta = Pasta::baked();
        let hash_of = |c: Vec<Fp>| -> Fp {
            let mut dr = Emulator::execute();
            let poly =
                WitnessedPolynomial::alloc(&mut dr, 4, Always::maybe_just(|| c)).expect("alloc");
            let hash = poly
                .hash_commitment(&mut dr, Pasta::circuit_poseidon(pasta))
                .expect("hash");
            *hash.value().take()
        };

        assert_eq!(hash_of(coeffs(&[1, 2, 3])), hash_of(coeffs(&[1, 2, 3])));
        assert_ne!(hash_of(coeffs(&[1, 2, 3])), hash_of(coeffs(&[1, 2, 4])));
        // Zero padding is part of the capacity, so a shorter vector hashes
        // like its padded form.
        assert_eq!(hash_of(coeffs(&[1, 2, 3])), hash_of(coeffs(&[1, 2, 3, 0])));
    }
}
