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
    `(com, x, y, coefficients)`: enforced natively at fuse time (evaluation
    and commitment binding both checked; invalid witnesses rejected), with
    claim instances persisted on the `Proof`. Recursive enforcement via the
    PCS `(P, u, v)` accumulator (`compute_v` slots and the nested endoscaling
    chain) remains future work.
  - `Application::commit_polynomial` — the framework's poly-query commitment:
    an unblinded host-curve Pedersen commitment carried onto the nested curve
    via the standard bridge encoding, witnessable in-circuit.

### Changed

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
