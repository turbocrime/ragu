# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Polynomial-query oracle for PCD steps (continues #701/#714/#783):
  - `StepCtx::derive_challenge` — sound Fiat–Shamir challenges: the in-circuit
    Poseidon sponge hash of any `ChallengeInput` (elements, points, and
    compositions), with real values available at witness time. Each call still
    records an induced-stage layout for the future succinct-commitment
    optimization.
  - `ragu_pcd::oracle::WitnessedPolynomial` — sound in-circuit polynomial
    oracle: witness coefficients in-circuit, evaluate via Horner, and bind
    across PCD nodes with a Poseidon hash commitment exposed through headers.
  - `StepCtx::enforce_poly_query` — succinct poly-query claims
    `(com, x, y, coefficients)`, **enforced recursively by the proof system**:
    - Every application circuit exposes `NUM_POLY_QUERY_SLOTS` claim slots in
      its public instance (unused slots hold a canonical padding claim),
      binding each claim's commitment point and `(x, y)` opening to the
      circuit's `k(Y)` — computed in-circuit by `outer_collapse` and
      recomputed by the top-level verifier.
    - When a claim-bearing proof is fused as a child, the parent folds the
      quotient `(p(X) − y)/(X − x)` into `f(X)`, beta-accumulates `p(X)` into
      the PCS `(P, u, v)` accumulator (the claim's host commitment enters the
      nested endoscaling points list, checked by the `Loading` and `Copying`
      circuits against the child's transcript-bound eval bridge stage), and
      the `compute_v` circuit re-derives the matching terms from the
      instance-bound claim data.
    - A root proof's own claims (not yet folded by a parent) are checked
      natively by `Application::verify` against the carried claim
      polynomials: evaluation, host-commitment binding, and the bridge to
      the instance commitment.
    - The fuse raising a claim still pre-checks it natively, so an honest
      prover with a dishonest witness fails early with `InvalidWitness`.
    - A corrupted claim instance (simulating a malicious prover skipping the
      native pre-check) is rejected by the circuits: directly at root verify,
      and recursively when fused as a child
      (`tests/recursive_claims.rs`, behind `unstable-fuzzing`).
  - `Application::commit_polynomial` — the framework's poly-query commitment:
    an unblinded host-curve Pedersen commitment carried onto the nested curve
    via the standard bridge encoding, witnessable in-circuit.

### Changed

- Poly-query claim slots are part of every application circuit's structure:
  a step body may call `enforce_poly_query` at most `NUM_POLY_QUERY_SLOTS`
  (currently 4) times, and the call count must be witness-independent.
  `Proof::application_claims()` now always returns exactly
  `NUM_POLY_QUERY_SLOTS` instances (real claims first, padding after).
  Registry digests, the endoscaling points count (37 → 45), and several
  internal stage widths changed accordingly; the maximum `HEADER_SIZE`
  shrinks slightly because the claim slots share `outer_collapse`'s
  gate budget with headers.
- `ApplicationBuilder::new` now takes the cycle parameters (and `finalize`
  no longer does); step bodies need Poseidon parameters on every driver.
- `StepCtx` is parameterized by the `Cycle` (not the nested curve) and exposes
  `poseidon()`; `Step::witness` impls take `StepCtx<'_, 'dr, D, C>`.
- `Pcd::proof` is now public, matching the mock.

## [0.0.0] - 2025-03-15

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/ragu/compare/ragu-0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/ragu/releases/tag/ragu-0.0.0
