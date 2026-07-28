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
pub mod poly_commitment;
mod proof;
mod slot_vec;
pub mod step;
mod verify;

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::{any::TypeId, cell::OnceCell, marker::PhantomData};

use header::Header;
pub use poly_commitment::{PolyCommitment, PolyQueryHandle};
pub use proof::{ClaimOpening, Pcd, Proof};
use ragu_arithmetic::{CryptoRngCore, Cycle};
use ragu_circuits::{
    polynomials::Rank,
    registry::{Registry, RegistryBuilder},
    staging::MultiStage,
};
use ragu_core::{Error, Result};

use step::{
    Step,
    internal::adapter::{Adapter, PendingStep},
};

/// Domain separation tag for Ragu PCD protocol.
// FIXME: choose a permanent domain separation tag before release.
pub(crate) const RAGU_TAG: &[u8] = b"FIXME";

/// Number of **polynomials** a step may witness — the expensive half of a
/// poly-query.
///
/// Each [`StepCtx::witness_polynomial`](step::StepCtx::witness_polynomial)
/// call occupies one slot. A polynomial slot costs, per step: a bridge stage
/// (and therefore a nested commitment), a carried polynomial, a host
/// commitment with its multi-scalar multiplication, and one endoscaling point
/// per child in the next fuse. The MSM is the part that matters — under the
/// framework's cost model, committed-oracle count drives prover wall-clock
/// while gates under the 2048-gate cap are nearly free.
///
/// Unused slots are filled with the canonical padding claim — the constant
/// polynomial $1$ opened at $x = 0$ to $y = 1$ — so every application circuit
/// has a uniform instance shape.
///
/// See [`NUM_QUERY_SLOTS`] for the cheap half, and
/// [what caps them](NUM_QUERY_SLOTS#what-caps-these-and-what-they-trade-against)
/// for the budget the two share.
pub const NUM_POLY_SLOTS: usize = 8;

/// Number of **evaluations** a step may enforce — the cheap half of a
/// poly-query.
///
/// Each [`StepCtx::enforce_poly_query`](step::StepCtx::enforce_poly_query)
/// call occupies one slot; a step body may call it at most this many times,
/// and the call count must not depend on witness values (it is part of the
/// circuit structure). A query slot costs one entry in the application
/// circuit's public instance, one quotient in `_08_f`, and one triple in
/// `compute_v` — no commitment, no MSM, no endoscaling point.
///
/// The slots are bound by the circuit's $k(Y)$ public-input polynomial and
/// recursively enforced at the next fuse via the PCS $(P, u, v)$ accumulator.
///
/// Kept distinct from [`NUM_POLY_SLOTS`] so that opening one polynomial at
/// several points spends the cheap resource rather than the expensive one.
///
/// # What caps these, and what they trade against
///
/// Not a consumer's choice, and not the endoscaling budget — each polynomial
/// slot does add one host commitment per child to the point list the next fuse
/// endoscales (see `NUM_ENDOSCALING_POINTS` in the `nested` module), but that
/// budget has room. The binding circuit is `outer_collapse`, the largest
/// internal circuit, which absorbs the elements each slot adds per child to the
/// application $k(Y)$: `com.x` and `com.y` for a polynomial, `x` and `y` for a
/// query.
///
/// They share that budget with `HEADER_SIZE`, at roughly 12 gates per welded
/// slot against 13 per header element — so **a claim slot costs about one
/// element of header**. Measured against `outer_collapse`'s 2048-gate bound,
/// with the two counts still equal:
///
/// | slots | header | gates |
/// | --- | --- | --- |
/// | 4 | 100 | 2044 |
/// | 8 | 90 | 1962 |
/// | 8 | 84 | 1884 |
/// | 8 | 60 | 1572 |
///
/// The numbers are one set, not independent knobs, and `internal::tests` pins
/// them: `HEADER_SIZE` there is the widest header the framework claims to
/// support, so changing any of them without re-measuring
/// `test_internal_circuit_constraint_counts` fails there.
///
/// An application that needs a wider header than the pinned one is not stuck
/// with a compile-time compromise: it picks its own `HEADER_SIZE`, and
/// [`finalize`](ApplicationBuilder::finalize) either fits or returns
/// `GateBoundExceeded`. Capacity is settled at finalization, against the
/// header that application actually configured.
pub const NUM_QUERY_SLOTS: usize = 8;

/// Maximum element width of a single
/// [`StepCtx::derive_challenge`](step::StepCtx::derive_challenge) input.
///
/// The width of a challenge input is a **compile-time** property of its type
/// ([`ChallengeInput::ELEMENTS`](framework_hooks::ChallengeInput::ELEMENTS)),
/// and exceeding this bound is a compile error, not a runtime one. (It is a
/// post-monomorphization error, so it surfaces on `cargo build`/`cargo test`
/// rather than `cargo check`.) Circuit structure must not depend on witness
/// values, and a challenge input whose width is only known at runtime — a
/// `Vec`, a slice, a polynomial with a runtime capacity — cannot offer that
/// guarantee. Compress such data into a single binding element first, the way
/// [`witness_polynomial`](step::StepCtx::witness_polynomial) reduces a whole
/// polynomial to one in-circuit commitment point, and derive the challenge from
/// that.
///
/// This is the width of the *stage* each slot commits. Fixing it at compile
/// time is what lets that stage be one type chained [`NUM_CHALLENGE_SLOTS`]
/// times, with narrower inputs zero-padded into the stage for free.
///
/// # Cost
///
/// `CHALLENGE_WIDTH` wires — `CHALLENGE_WIDTH / 2` gates — per slot in every
/// application circuit, reserved whether or not the step derives a challenge.
///
/// It costs **no permutations**. The challenge is not a hash of the input: it
/// is the hash of the input stage's *commitment*, bridged onto the nested
/// curve, so the sponge absorbs two coordinates regardless of how wide the
/// input was. That hash is paid once per `(child, slot)` pair by the internal
/// `challenge_binding` circuit, out of the framework's budget rather than the
/// step's. Raising this constant therefore costs wires and nothing else.
///
/// The value accommodates an [`Element`](ragu_primitives::Element), a
/// [`Point`](ragu_primitives::Point), or a pair of either without padding.
pub const CHALLENGE_WIDTH: usize = 4;

/// Number of Fiat–Shamir challenge slots a step body may use.
///
/// Each [`StepCtx::derive_challenge`](step::StepCtx::derive_challenge) call
/// occupies one slot; a step body may call it at most this many times, and the
/// call count must not depend on witness values (it is part of the circuit
/// structure, checked by the adapter's determinism guard).
///
/// Unused slots are padded, like the poly-query slots: the all-zero stage,
/// blinded, with its challenge derived honestly. The parent's binding circuit
/// re-derives every slot without knowing which ones the step actually used, so
/// the padding is what keeps that circuit uniform.
///
/// # Cost
///
/// Two places, neither of them the step's Poseidon budget:
///
/// * every application circuit reserves
///   `NUM_CHALLENGE_SLOTS * CHALLENGE_WIDTH / 2` gates for the stages, whether
///   or not it derives anything;
/// * the recursion pays `2 * NUM_CHALLENGE_SLOTS` permutations per fuse in the
///   internal `challenge_binding` circuit — at two slots, 1536 of its own 2048
///   gates — plus `2 * NUM_CHALLENGE_SLOTS` endoscaling points and one bonding
///   mask per slot on each curve.
///
/// So raising this constant is charged almost entirely to the framework's
/// circuits, not to the steps that use it. Two is the smallest count that lets
/// a step handle more than one polynomial at a time, which one would not.
pub const NUM_CHALLENGE_SLOTS: usize = 2;

/// Builder for an [`Application`] for proof-carrying data.
pub struct ApplicationBuilder<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    native_registry: RegistryBuilder<'params, C::CircuitField, R>,
    nested_registry: RegistryBuilder<'params, C::ScalarField, R>,
    num_application_steps: usize,
    /// Application step adapters constructed at [`register`](Self::register)
    /// but not yet handed to the registry.
    ///
    /// Hand-over measures a circuit — the registry synthesizes it and freezes
    /// its shape — and a step circuit's padded shape depends on the maximum
    /// slot counts over every registered step. That maximum is settled only
    /// when registration closes, so hand-over waits for
    /// [`finalize`](Self::finalize).
    held_steps: Vec<Box<dyn PendingStep<'params, C, R> + 'params>>,
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
            held_steps: Vec::new(),
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

        // Building the adapter discovers the step's hook-call layout — its
        // `derive_challenge` and `enforce_poly_query` counts — by dry-running
        // the witness body. That dry run is structure-only, so it needs no
        // cycle parameters, which is what lets adapter construction stay eager
        // here while `finalize` remains where the parameters arrive.
        //
        // The adapter is held rather than registered: hand-over to the
        // registry would freeze the circuit's shape now, and its shape is not
        // knowable until every step has registered (see
        // [`PendingStep`](step::internal::adapter::PendingStep)).
        let adapter = Adapter::<C, S, R, HEADER_SIZE>::new(step, None)?;
        self.held_steps.push(Box::new(adapter));
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
        // Registration is closed, so the shape set is settled: collect every
        // step's discovered plan before hand-over freezes the circuits. The
        // internal steps are constructed here too (their discovery dry run is
        // structure-only), so their plans join the table in circuit-index
        // order: internal steps first, then application steps.
        let rerandomize = Adapter::<C, _, R, HEADER_SIZE>::new(
            step::internal::rerandomize::Rerandomize::<()>::new(),
            Some(params),
        )?;
        let trivial = Adapter::<C, _, R, HEADER_SIZE>::new(
            step::internal::trivial::Trivial::new(),
            Some(params),
        )?;
        let mut step_plans = Vec::with_capacity(step::NUM_INTERNAL_STEPS + self.held_steps.len());
        step_plans.push(rerandomize.layout());
        step_plans.push(trivial.layout());
        step_plans.extend(self.held_steps.iter().map(|held| held.layout()));

        // The held application step adapters can be handed to the registry:
        // their circuits are measured now, with every step known. Registry
        // indexing is by category, not hand-over order, so registering them
        // here rather than in `register` changes nothing downstream.
        for held in self.held_steps.drain(..) {
            self.native_registry = held.register(self.native_registry)?;
        }

        // Build the native registry:
        // 1. Application circuits (registered just above)
        // 2. Internal circuits and masks
        // 3. Internal steps
        let (total_circuits, log2_circuits) =
            internal::native::total_circuit_counts(self.num_application_steps, NUM_CHALLENGE_SLOTS);

        // First, register internal circuits and masks
        self.native_registry = internal::native::register_all::<C, R, HEADER_SIZE>(
            self.native_registry,
            params,
            log2_circuits,
            framework_hooks::HookLayout::padded(),
        )?;

        // Then, register internal steps
        self.native_registry = self
            .native_registry
            .register_internal_step(MultiStage::new(rerandomize))?;
        self.native_registry = self
            .native_registry
            .register_internal_step(MultiStage::new(trivial))?;

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
            step_plans,
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
    /// Every step's discovered plan, in circuit-index order within the step
    /// block: internal steps (rerandomize, trivial) first, then application
    /// steps in registration order. Index `i` here corresponds to circuit
    /// index `InternalCircuitIndex::NUM + i`. Collected by
    /// [`ApplicationBuilder::finalize`] before hand-over; this table — not
    /// any list a proof carries — is what fuse and verify consult for a
    /// child's shape, keyed by its registry-committed circuit index.
    step_plans: Vec<framework_hooks::HookLayout>,
    /// Cached seeded trivial proof for rerandomization.
    seeded_trivial: OnceCell<Proof<C, R>>,
    /// Test-only: skip the prover-side poly-query pre-check. See
    /// [`ApplicationBuilder::skip_claim_precheck_for_testing`].
    #[cfg(feature = "unstable-fuzzing")]
    pub(crate) skip_claim_precheck: bool,
    _marker: PhantomData<[(); HEADER_SIZE]>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// The discovered plan of the step occupying circuit `index`, or `None`
    /// if that index is an internal circuit (which is not a step and has no
    /// plan). See [`Self::step_plans`] for the table's provenance.
    #[allow(dead_code)] // consumed when fuse/verify select variants by plan
    pub(crate) fn step_plan(
        &self,
        index: ragu_circuits::registry::CircuitIndex,
    ) -> Option<framework_hooks::HookLayout> {
        usize::from(index)
            .checked_sub(internal::native::InternalCircuitIndex::NUM)
            .and_then(|i| self.step_plans.get(i))
            .copied()
    }

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

    /// Whether the fuse-time poly-query pre-check runs. Always `true` outside
    /// the `unstable-fuzzing` feature, which is the only thing that can turn it
    /// off.
    #[cfg_attr(
        feature = "unstable-fuzzing",
        doc = "See [`ApplicationBuilder::skip_claim_precheck_for_testing`]."
    )]
    pub(crate) fn claim_precheck_enabled(&self) -> bool {
        #[cfg(feature = "unstable-fuzzing")]
        {
            !self.skip_claim_precheck
        }
        #[cfg(not(feature = "unstable-fuzzing"))]
        {
            true
        }
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
