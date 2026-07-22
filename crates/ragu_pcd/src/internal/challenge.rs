//! Derive a Fiat–Shamir challenge by committing to a polynomial and hashing
//! the commitment.
//!
//! This bundles the per-stage sub-step that `fuse` performs when turning a
//! committed (partial) trace into a challenge: Pedersen-commit the polynomial,
//! absorb the resulting curve point into the [`Transcript`], and squeeze a
//! challenge from it. It is the prover-side mechanic behind a derived challenge
//! — the same "commit a stage, hash its commitment" pattern already spelled out
//! inline in the fuse stages (see [`crate::fuse`]).

use alloc::vec;

use ragu_arithmetic::{CurveAffine, Cycle, FixedGenerators, PoseidonPermutation, ff::PrimeField};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Error, Result, drivers::Driver};
use ragu_primitives::{Element, GadgetExt, Point};

use super::transcript::Transcript;

/// Commit to `poly` and derive a challenge by hashing the commitment.
///
/// `poly` is a polynomial over `C::ScalarExt`; committing it with `generators`
/// yields a point on `C`, whose coordinates live in `C::Base`. Because the
/// driver `dr` and the `transcript` both work over `C::Base`, the commitment is
/// absorbed directly and the squeezed challenge is a `C::Base` element.
///
/// In a [`Cycle`](ragu_arithmetic::Cycle) this is used in both directions: a
/// `ScalarField` polynomial committed on the `NestedCurve` yields a
/// `CircuitField` challenge, while a `CircuitField` polynomial committed on the
/// `HostCurve` yields a `ScalarField` challenge — the caller picks `C` and the
/// matching generators.
///
/// Returns the commitment point alongside the squeezed challenge.
// TODO: this is the prover-side mechanic for the future succinct-challenge
// optimization (committing each induced stage and hashing the commitment
// instead of hashing the stage in the application circuit); for now it is
// exercised only by its unit tests.
#[allow(dead_code)]
pub(crate) fn commit_and_challenge<'dr, D, C, P, R>(
    dr: &mut D,
    transcript: &mut Transcript<'dr, D, P>,
    generators: &impl FixedGenerators<C>,
    poly: &sparse::Polynomial<C::ScalarExt, R>,
) -> Result<(C, Element<'dr, D>)>
where
    D: Driver<'dr, F = C::Base>,
    D::F: PrimeField,
    C: CurveAffine,
    P: PoseidonPermutation<C::Base>,
    R: Rank,
{
    let commitment = poly.commit_to_affine::<C>(generators);
    Point::constant(dr, commitment)?.write(dr, transcript)?;
    let challenge = transcript.challenge(dr)?;
    Ok((commitment, challenge))
}

/// Encodes a host-curve point as a nested-curve commitment via the standard
/// bridge encoding: the point's affine coordinates (two `ScalarField`
/// elements) become the coefficients of a two-term polynomial committed on the
/// nested curve. Mirrors the bridge stages (e.g. `nested::stages::f`), which
/// witness a host point as two scalar-field wires of a nested rx polynomial.
///
/// The bridge commitment is unblinded: it binds the host point
/// deterministically. Hiding (a blinded bridge, coordinated with the nested
/// stage masks) is future work.
///
/// # Errors
///
/// Returns [`Error::InvalidWitness`] if `host` is the identity, which has no
/// affine coordinates (and could not be witnessed as a `Point` in-circuit).
pub(crate) fn bridge_commitment<C: Cycle, R: Rank>(
    params: &C::Params,
    host: C::HostCurve,
) -> Result<C::NestedCurve> {
    let coordinates = host.coordinates().into_option().ok_or_else(|| {
        Error::InvalidWitness("identity commitment cannot be bridged to the nested curve".into())
    })?;
    let bridge = sparse::Polynomial::<C::ScalarField, R>::from_coeffs(vec![
        *coordinates.x(),
        *coordinates.y(),
    ]);
    Ok(bridge.commit_to_affine::<C::NestedCurve>(C::nested_generators(params)))
}

/// Commits to a `CircuitField` polynomial in the framework's poly-query
/// commitment scheme: an (unblinded) Pedersen commitment on the host curve,
/// carried onto the nested curve via [`bridge_commitment`] so the result can
/// be witnessed and manipulated in-circuit.
///
/// This is the commitment that
/// [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) claims are
/// checked against at fuse time. Exposed to applications as
/// [`Application::commit_polynomial`](crate::Application::commit_polynomial).
///
/// # Errors
///
/// Returns [`Error::InvalidWitness`] if the polynomial's host commitment is
/// the identity (e.g. the zero polynomial).
pub(crate) fn commit_polynomial<C: Cycle, R: Rank>(
    params: &C::Params,
    polynomial: &sparse::Polynomial<C::CircuitField, R>,
) -> Result<C::NestedCurve> {
    let host = polynomial.commit_to_affine::<C::HostCurve>(C::host_generators(params));
    bridge_commitment::<C, R>(params, host)
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::Cycle;
    use ragu_circuits::polynomials::{TestRank, sparse};
    use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
    use ragu_pasta::Pasta;

    use super::*;
    use crate::{RAGU_TAG, internal::transcript::Transcript};

    type C = Pasta;
    type R = TestRank;
    type Scalar = <C as Cycle>::ScalarField;
    type Circuit = <C as Cycle>::CircuitField;
    type Nested = <C as Cycle>::NestedCurve;

    fn poly_from(coeffs: &[u64]) -> sparse::Polynomial<Scalar, R> {
        sparse::Polynomial::from_coeffs(coeffs.iter().map(|c| Scalar::from(*c)).collect())
    }

    /// The returned commitment is exactly the Pedersen commitment to the
    /// polynomial, and the same `(poly, transcript tag)` always produces the
    /// same challenge.
    #[test]
    fn commitment_matches_and_challenge_is_deterministic() -> Result<()> {
        let params = C::generate();
        let generators = C::nested_generators(&params);
        let poly = poly_from(&[3, 1, 4, 1, 5]);

        let run = || -> Result<(Nested, Circuit)> {
            let mut dr = Emulator::execute();
            let mut transcript = Transcript::new(&mut dr, C::circuit_poseidon(&params), RAGU_TAG)?;
            let (commitment, challenge) = commit_and_challenge::<_, Nested, _, R>(
                &mut dr,
                &mut transcript,
                generators,
                &poly,
            )?;
            Ok((commitment, *challenge.value().take()))
        };

        let (commitment, challenge) = run()?;

        // The commitment is the standalone Pedersen commitment.
        assert_eq!(commitment, poly.commit_to_affine::<Nested>(generators));

        // Re-running from a fresh transcript with the same inputs is
        // deterministic.
        let (commitment_again, challenge_again) = run()?;
        assert_eq!(commitment, commitment_again);
        assert_eq!(challenge, challenge_again);

        Ok(())
    }

    /// Distinct polynomials bind to distinct challenges.
    #[test]
    fn distinct_polynomials_yield_distinct_challenges() -> Result<()> {
        let params = C::generate();
        let generators = C::nested_generators(&params);

        let challenge_for = |poly: &sparse::Polynomial<Scalar, R>| -> Result<Circuit> {
            let mut dr = Emulator::execute();
            let mut transcript = Transcript::new(&mut dr, C::circuit_poseidon(&params), RAGU_TAG)?;
            let (_, challenge) = commit_and_challenge::<_, Nested, _, R>(
                &mut dr,
                &mut transcript,
                generators,
                poly,
            )?;
            Ok(*challenge.value().take())
        };

        let a = challenge_for(&poly_from(&[1, 2, 3]))?;
        let b = challenge_for(&poly_from(&[1, 2, 4]))?;
        assert_ne!(a, b);

        Ok(())
    }
}
