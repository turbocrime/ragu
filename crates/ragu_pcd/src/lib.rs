//! Proof-carrying data framework for Ragu.
//!
//! This crate provides the top-level API for building PCD applications:
//!
//! - [`ApplicationBuilder`] / [`Application`] — configure, build, then
//!   [`seed`](Application::seed), [`fuse`](Application::fuse),
//!   [`rerandomize`](Application::rerandomize), and
//!   [`verify`](Application::verify) proofs.
//! - [`step::Step`] — the trait that defines computation nodes (transitions).
//! - [`header::Header`] — the trait that defines succinct state representations.
//! - [`Proof`] / [`Pcd`] — the proof and proof-carrying-data structures.

#![no_std]
#![allow(clippy::type_complexity, clippy::too_many_arguments)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1/favicon-32x32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1/rustdoc-128x128.png")]

#[cfg(not(feature = "alloc"))]
compile_error!("`ragu_pcd` requires the `alloc` feature to be enabled.");
extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

pub mod framework_hooks;
mod fuse;
#[cfg(feature = "unstable-fuzzing")]
pub mod fuzz_utils;
pub mod header;
mod internal;
pub mod oracle;
pub mod poly_commitment;
mod proof;
pub mod step;
mod verify;

use alloc::collections::BTreeMap;
use core::{any::TypeId, cell::OnceCell, marker::PhantomData};

use header::Header;
pub use poly_commitment::{PolyCommitment, PolyQueryHandle};
pub use proof::{ClaimOpening, Pcd, Proof};
use ragu_arithmetic::{CryptoRngCore, Cycle};
use ragu_circuits::{
    polynomials::Rank,
    registry::{Registry, RegistryBuilder},
};
use ragu_core::{Error, Result};
use step::{Step, internal::adapter::Adapter};

/// Domain separation tag for Ragu PCD protocol.
// FIXME: choose a permanent domain separation tag before release.
pub(crate) const RAGU_TAG: &[u8] = b"FIXME";

/// Number of polynomial-query claim slots every application circuit exposes in
/// its public instance.
///
/// Each [`StepCtx::enforce_poly_query`](step::StepCtx::enforce_poly_query)
/// call occupies one slot; a step body may call it at most this many times,
/// and the call count must not depend on witness values (it is part of the
/// circuit structure). Unused slots are filled with the canonical padding
/// claim — the constant polynomial $1$ opened at $x = 0$ to $y = 1$ — so
/// every application circuit has a uniform instance shape.
///
/// The slots are bound by the circuit's $k(Y)$ public-input polynomial and
/// recursively enforced at the next fuse via the PCS $(P, u, v)$ accumulator.
///
/// The specific value is governed by the enforcement circuit's endoscaling
/// budget, not by any consumer. Each slot contributes one host commitment per
/// child proof to the point list the next fuse endoscales, so
/// `NUM_ENDOSCALING_POINTS = 37 + 2 * NUM_POLY_QUERY_SLOTS` (see the `nested`
/// module); the resulting number of endoscaling steps — at four endoscalings
/// per step — must fit the enforcement circuit's target size. Raising this
/// constant widens that circuit; it is capped by what fits, not by the needs
/// of any particular claim producer.
pub const NUM_POLY_QUERY_SLOTS: usize = 4;

/// Maximum element width of a single
/// [`StepCtx::derive_challenge`](step::StepCtx::derive_challenge) input.
///
/// The width of a challenge input is a **compile-time** property of its type
/// ([`ChallengeInput::ELEMENTS`](framework_hooks::ChallengeInput::ELEMENTS)),
/// and exceeding this bound is a compile error, not a runtime one. (It is a
/// post-monomorphization error, so it surfaces on `cargo build`/`cargo test`
/// rather than `cargo check`.) Circuit
/// structure must not depend on witness values, and a challenge input whose
/// width is only known at runtime — a `Vec`, a slice, a polynomial with a
/// runtime capacity — cannot offer that guarantee. Compress such data into a
/// single binding element first (for example
/// [`WitnessedPolynomial::hash_commitment`](oracle::WitnessedPolynomial::hash_commitment))
/// and derive the challenge from that.
///
/// The value is set by the Poseidon rate. The challenge is a sponge hash of the
/// input, absorbs merely buffer, and the permutation is triggered by the squeeze
/// (or by an absorb overflowing the `RATE = 4` buffer) — so every input of four
/// elements or fewer, an [`Element`](ragu_primitives::Element), a
/// [`Point`](ragu_primitives::Point), or a pair of either, costs exactly one
/// permutation, and the fifth element costs a second. Measured in application
/// gates: 288 for one through four elements, 576 from five.
///
/// Raising this constant therefore makes no existing derivation more expensive
/// — it only admits wider inputs, at one further permutation per additional
/// four elements.
///
/// It is also the width the future per-challenge stage will commit (see
/// `POLY_QUERY_SOUNDNESS.md`): a fixed width is what lets that stage be one
/// const-generic type chained [`NUM_CHALLENGE_SLOTS`] times, with narrower
/// inputs zero-padded into the stage for free.
pub const CHALLENGE_WIDTH: usize = 4;

/// Number of Fiat–Shamir challenge slots a step body may use.
///
/// Each [`StepCtx::derive_challenge`](step::StepCtx::derive_challenge) call
/// occupies one slot; a step body may call it at most this many times, and the
/// call count must not depend on witness values (it is part of the circuit
/// structure, checked by the adapter's determinism guard).
///
/// The value matches [`NUM_POLY_QUERY_SLOTS`] because one challenge per opened
/// polynomial is the natural ceiling: a step derives a challenge to *use* it,
/// and the succinct way to use one is to open a committed polynomial there.
///
/// Cost agrees. The derivation is synthesized in the *application* circuit, on
/// the step's own driver, so it spends the step's gate budget: one call costs
/// **288 gates** (576 constraints) — one Poseidon permutation, and the same at
/// any width up to [`CHALLENGE_WIDTH`] — against a budget of roughly 2048. Four
/// calls is already over half of it. Note that this is why unused slots are
/// *not* padded, unlike the poly-query slots: an unused claim slot is four
/// wires, but an unused challenge slot would be a whole permutation.
pub const NUM_CHALLENGE_SLOTS: usize = 4;

/// Builder for an [`Application`] for proof-carrying data.
pub struct ApplicationBuilder<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    native_registry: RegistryBuilder<'params, C::CircuitField, R>,
    nested_registry: RegistryBuilder<'params, C::ScalarField, R>,
    num_application_steps: usize,
    header_map: BTreeMap<header::Suffix, TypeId>,
    /// Test-only: see [`ApplicationBuilder::skip_claim_precheck_for_testing`].
    #[cfg(feature = "unstable-fuzzing")]
    skip_claim_precheck: bool,
    _marker: PhantomData<[(); HEADER_SIZE]>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Default
    for ApplicationBuilder<'_, C, R, HEADER_SIZE>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>
    ApplicationBuilder<'params, C, R, HEADER_SIZE>
{
    /// Create an empty [`ApplicationBuilder`] for proof-carrying data. The
    /// cycle's runtime parameters are not needed until
    /// [`finalize`](Self::finalize).
    pub fn new() -> Self {
        ApplicationBuilder {
            native_registry: RegistryBuilder::new(),
            nested_registry: RegistryBuilder::new(),
            num_application_steps: 0,
            header_map: BTreeMap::new(),
            #[cfg(feature = "unstable-fuzzing")]
            skip_claim_precheck: false,
            _marker: PhantomData,
        }
    }

    /// Register a new application-defined [`Step`] in this context. The
    /// provided [`Step`]'s [`INDEX`](Step::INDEX) must be the next sequential
    /// index that has not been inserted yet.
    ///
    /// # Errors
    ///
    /// Returns an error if the step's index is not the next sequential index,
    /// or if any of the step's header suffixes conflict with an
    /// already-registered header type.
    pub fn register<S: Step<C> + 'params>(mut self, step: S) -> Result<Self> {
        S::INDEX.assert_index(self.num_application_steps)?;

        self.prevent_duplicate_suffixes::<S::Output>()?;
        self.prevent_duplicate_suffixes::<S::Left>()?;
        self.prevent_duplicate_suffixes::<S::Right>()?;

        // Constructing the adapter discovers the step's hook-call layout —
        // its `derive_challenge` call widths and poly-query claim count — via
        // a dry run of the witness body. This is param-free: discovery uses the
        // baked Poseidon constants and the padding claim is witnessed (not baked
        // into the circuit) at proving time, so an application circuit's
        // identity does not depend on the runtime generators.
        let adapter = Adapter::<C, S, R, HEADER_SIZE>::new(step)?;

        self.native_registry = self.native_registry.register_circuit(adapter)?;
        self.num_application_steps += 1;

        Ok(self)
    }

    /// Register `count` trivial circuits to simulate application steps
    /// registration.
    ///
    /// This is useful for testing internal circuit behavior with a non-zero
    /// number of application steps, without needing real [`Step`]
    /// implementations.
    #[cfg(test)]
    pub(crate) fn register_dummy_circuits(mut self, count: usize) -> Result<Self> {
        for _ in 0..count {
            self.native_registry = self.native_registry.register_circuit(())?;
            self.num_application_steps += 1;
        }
        Ok(self)
    }

    /// Perform finalization and optimization steps to produce the
    /// [`Application`].
    ///
    /// # Errors
    ///
    /// Returns an error if internal circuit registration or registry
    /// finalization fails.
    pub fn finalize(
        mut self,
        params: &'params C::Params,
    ) -> Result<Application<'params, C, R, HEADER_SIZE>> {
        // Build the native registry:
        // 1. Application circuits (already registered)
        // 2. Internal circuits and masks
        // 3. Internal steps
        let (total_circuits, log2_circuits) =
            internal::native::total_circuit_counts(self.num_application_steps);

        // First, register internal circuits and masks
        self.native_registry = internal::native::register_all::<C, R, HEADER_SIZE>(
            self.native_registry,
            params,
            log2_circuits,
        )?;

        // Then, register internal steps
        self.native_registry =
            self.native_registry
                .register_internal_step(Adapter::<C, _, R, HEADER_SIZE>::new(
                    step::internal::rerandomize::Rerandomize::<()>::new(),
                )?)?;
        self.native_registry =
            self.native_registry
                .register_internal_step(Adapter::<C, _, R, HEADER_SIZE>::new(
                    step::internal::trivial::Trivial::new(),
                )?)?;

        assert_eq!(
            self.native_registry.log2_circuits(),
            log2_circuits,
            "log2_circuits mismatch"
        );
        assert_eq!(
            self.native_registry.num_circuits(),
            total_circuits,
            "final circuit count mismatch"
        );

        // Register nested internal circuits (no application steps, no headers).
        self.nested_registry = internal::nested::register_all::<C, R>(self.nested_registry)?;

        Ok(Application {
            native_registry: self.native_registry.finalize()?,
            nested_registry: self.nested_registry.finalize()?,
            params,
            num_application_steps: self.num_application_steps,
            seeded_trivial: OnceCell::new(),
            #[cfg(feature = "unstable-fuzzing")]
            skip_claim_precheck: self.skip_claim_precheck,
            _marker: PhantomData,
        })
    }

    /// Disables the fuse-time poly-query pre-check, modelling a malicious
    /// prover who simply does not run it.
    ///
    /// The pre-check in `fuse::_01_application` runs on the prover and
    /// carries no soundness weight by design; disabling it lets tests
    /// distinguish what the *circuits* enforce from what the honest prover
    /// merely declines to do.
    #[cfg(feature = "unstable-fuzzing")]
    pub fn skip_claim_precheck_for_testing(mut self) -> Self {
        self.skip_claim_precheck = true;
        self
    }

    fn prevent_duplicate_suffixes<H: Header<C::CircuitField>>(&mut self) -> Result<()> {
        match self.header_map.get(&H::SUFFIX) {
            Some(ty) => {
                if *ty != TypeId::of::<H>() {
                    return Err(Error::Initialization(
                        "two different Header implementations using the same suffix".into(),
                    ));
                }
            }
            None => {
                self.header_map.insert(H::SUFFIX, TypeId::of::<H>());
            }
        }

        Ok(())
    }
}

/// The recursion context that is used to create and verify proof-carrying data.
pub struct Application<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    native_registry: Registry<'params, C::CircuitField, R>,
    nested_registry: Registry<'params, C::ScalarField, R>,
    params: &'params C::Params,
    num_application_steps: usize,
    /// Cached seeded trivial proof for rerandomization.
    seeded_trivial: OnceCell<Proof<C, R>>,
    /// Test-only: skip the prover-side poly-query pre-check. See
    /// [`ApplicationBuilder::skip_claim_precheck_for_testing`].
    #[cfg(feature = "unstable-fuzzing")]
    pub(crate) skip_claim_precheck: bool,
    _marker: PhantomData<[(); HEADER_SIZE]>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Seed a new computation by running a step with trivial inputs.
    ///
    /// This is the entry point for creating leaf nodes in a PCD tree.
    /// Internally creates minimal trivial proofs with `()` headers and fuses
    /// them with the provided step to produce a valid proof.
    pub fn seed<'source, RNG: CryptoRngCore, S: Step<C, Left = (), Right = ()>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
    ) -> Result<(Pcd<C, R, S::Output>, S::Aux<'source>)> {
        self.fuse(rng, step, witness, self.trivial_pcd(), self.trivial_pcd())
    }

    /// Returns a seeded trivial proof for use in rerandomization.
    ///
    /// A seeded trivial is a trivial proof that has been through `seed()`
    /// (folded with itself). This gives it valid proof structure, avoiding
    /// base case detection issues.
    ///
    /// The proof is lazily created on first use and cached; subsequent calls
    /// return the same (non-random) proof.
    fn seeded_trivial_pcd<RNG: CryptoRngCore>(&self, rng: &mut RNG) -> Pcd<C, R, ()> {
        self.seeded_trivial
            .get_or_init(|| {
                self.seed(rng, step::internal::trivial::Trivial::new(), ())
                    .expect("seeded trivial seed should not fail")
                    .0
                    .into_parts()
                    .0
            })
            .clone()
            .carry(())
    }

    /// Rerandomize proof-carrying data.
    ///
    /// This will internally fold the [`Pcd`] with a seeded trivial proof
    /// using an internal rerandomization step, such that the resulting proof
    /// is valid for the same [`Header`] but reveals nothing else about the
    /// original proof. As a result, [`Application::verify`] should produce the
    /// same result on the provided `pcd` as it would the output of this method.
    pub fn rerandomize<RNG: CryptoRngCore, H: Header<C::CircuitField>>(
        &self,
        pcd: Pcd<C, R, H>,
        rng: &mut RNG,
    ) -> Result<Pcd<C, R, H>> {
        // Seed a trivial proof for rerandomization.
        // TODO: this is a temporary hack that allows the base case logic to be simple
        let seeded_trivial = self.seeded_trivial_pcd(rng);

        // The Rerandomize step's witness() returns the left input's data as
        // output data, preserving it through rerandomization.
        self.fuse(
            rng,
            step::internal::rerandomize::Rerandomize::new(),
            (),
            pcd,
            seeded_trivial,
        )
        .map(|(pcd, ())| pcd)
    }

    /// Returns a reference to the native [`Registry`].
    pub fn native_registry(&self) -> &Registry<'_, C::CircuitField, R> {
        &self.native_registry
    }

    /// Commits to a `CircuitField` polynomial in the framework's poly-query
    /// commitment scheme, returning a [`PolyCommitment`] that bundles the
    /// polynomial with the nested-curve commitment derived from it.
    ///
    /// The commitment is an (unblinded) Pedersen commitment to the
    /// coefficients on the host curve, carried onto the nested curve via the
    /// framework's standard bridge encoding. Thread the returned
    /// [`PolyCommitment`] into a step's witness and turn it into an in-circuit
    /// [`PolyQueryHandle`] with
    /// [`StepCtx::witness_polynomial`](step::StepCtx::witness_polynomial);
    /// [`StepCtx::enforce_poly_query`](step::StepCtx::enforce_poly_query) then
    /// raises the opening claim. Because the commitment is derived from the
    /// polynomial here, the two cannot be mismatched by an honest caller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`] if the polynomial's commitment is
    /// the identity (e.g. the zero polynomial), which cannot be witnessed
    /// in-circuit.
    pub fn commit_polynomial(
        &self,
        polynomial: &ragu_circuits::polynomials::sparse::Polynomial<C::CircuitField, R>,
    ) -> Result<PolyCommitment<C, R>> {
        let host = internal::challenge::host_commitment::<C, R>(self.params, polynomial)?;
        Ok(PolyCommitment::new(polynomial.clone(), host))
    }
}
