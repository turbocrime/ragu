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
//!
//! # Slot capacities are declared per application
//!
//! How many polynomials a step may witness, how many openings it may enforce,
//! how many challenges it may derive and how wide each challenge is are **not**
//! framework constants — consumers' needs vary too widely for that. They are
//! parameters of [`ApplicationBuilder`], so a step's cost falls on the
//! application that registers it rather than on every application the framework
//! will ever host.
//!
//! They are declared rather than folded from the registered steps because
//! handing a circuit to the registry *measures* it: the registry synthesizes the
//! circuit and freezes its shape. A shape derived from a maximum over steps is
//! not settled until the last one arrives, which is what once forced hand-over
//! to wait for [`finalize`](ApplicationBuilder::finalize). Declared, an
//! application's shape is known before the first step registers, so
//! [`register`](ApplicationBuilder::register) hands each circuit over on the
//! spot.
//!
//! A capacity is uniform within one application because the internal circuits
//! read a child's instance as a fixed-width record and any step's proof may be
//! any fuse's child. Steps that use fewer slots than declared are padded up to
//! it, at a cost that does not grow with the capacity.
//!
//! What the capacities trade against is [`HEADER_SIZE`]: a claim slot adds
//! three elements to the child's $k(Y)$ and a header element adds one, both
//! absorbed by `outer_collapse` at roughly the same per-element rate. There is
//! no capacity arithmetic anywhere — an application is simply built, and if a
//! combination does not fit, `finalize` returns
//! [`GateBoundExceeded`](ragu_core::Error::GateBoundExceeded) and the numbers
//! come down.
//!
//! [`HEADER_SIZE`]: Application

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

use alloc::collections::BTreeMap;
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

use step::{Step, internal::adapter::Adapter};

/// Domain separation tag for Ragu PCD protocol.
// FIXME: choose a permanent domain separation tag before release.
pub(crate) const RAGU_TAG: &[u8] = b"FIXME";

/// Builder for an [`Application`] for proof-carrying data.
///
/// `CHALLENGE_WIDTH` is the widest input a
/// [`derive_challenge`](step::StepCtx::derive_challenge) call may pass, in
/// curve points. Every challenge slot's instance region holds exactly that
/// many, with the positions a caller leaves empty taking a sentinel.
///
/// Points are the natural unit here: a caller passes points, and the instance
/// stores points. What the width *costs* is derived from it —
/// [`ChallengeLayout::permutations`](framework_hooks::ChallengeLayout::permutations)
/// gives the `⌈2·width / RATE⌉` absorb permutations, paid by the internal
/// `challenge_binding` circuit once per `(child, slot)` rather than out of any
/// step's gate budget.
///
/// `POLYS` is how many polynomials any one step may witness. Declared for the
/// same reason: a polynomial slot is the expensive axis — a bridge stage, a
/// commitment, an MSM, and an endoscaling point per child — so how many an
/// application is willing to pay for is its choice, not something to be learned
/// by running its steps.
///
/// `CLAIMS` is how many opening claims any one step may enforce. A claim is the
/// cheap axis — one instance triple, one `_08_f` quotient, one `compute_v`
/// triple, no commitment and no endoscaling point — and claim slots trade
/// against `HEADER_SIZE`, since both are terms in the same $k(Y)$ Horner loop.
/// An application that asks for more of either than its circuits can hold fails
/// at [`finalize`](ApplicationBuilder::finalize) with
/// [`GateBoundExceeded`](ragu_core::Error::GateBoundExceeded); there is no
/// arithmetic to do in advance, just a number to lower.
///
/// `CHALLENGES` is how many [`derive_challenge`](step::StepCtx::derive_challenge)
/// calls any one step may make — the *number* of calls, where
/// `CHALLENGE_PERMUTATIONS` fixes how wide each one is.
///
/// Together with `HEADER_SIZE` these four are the whole of an application
/// circuit's instance width:
///
/// ```text
/// 3·HEADER_SIZE + 2·POLYS + 3·CLAIMS + CHALLENGES·(2·points + 1)
/// ```
///
/// Every term is declared, so a step's circuit shape is final the moment it
/// registers. That is the point of declaring them: hand-over to the registry
/// *measures* a circuit, and a shape folded from the steps is not settled until
/// the last step has arrived.
pub struct ApplicationBuilder<
    'params,
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
> {
    native_registry: RegistryBuilder<'params, C::CircuitField, R>,
    nested_registry: RegistryBuilder<'params, C::ScalarField, R>,
    num_application_steps: usize,
    header_map: BTreeMap<header::Suffix, TypeId>,
    /// Test-only: see [`ApplicationBuilder::skip_claim_precheck_for_testing`].
    #[cfg(feature = "unstable-fuzzing")]
    skip_claim_precheck: bool,
    _marker: PhantomData<[(); HEADER_SIZE]>,
}

impl<
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
> Default for ApplicationBuilder<'_, C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<
    'params,
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
> ApplicationBuilder<'params, C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>
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

    /// The widest input a [`derive_challenge`](step::StepCtx::derive_challenge)
    /// call may pass, in curve points.
    ///
    /// The declared `CHALLENGE_WIDTH`, verbatim. Known before any step
    /// registers, which is what lets the registration dry run witness the right
    /// number of points.
    fn challenge_width() -> usize {
        CHALLENGE_WIDTH
    }

    /// The application's slot capacity, straight from its declared parameters.
    ///
    /// Every application circuit exposes exactly these slots. Nothing is folded
    /// from the registered steps, so this is available before the first one
    /// arrives — which is what lets [`register`](Self::register) hand a circuit
    /// to the registry immediately instead of holding it until
    /// [`finalize`](Self::finalize).
    fn capacity() -> framework_hooks::HookLayout {
        framework_hooks::HookLayout {
            challenge: framework_hooks::ChallengeLayout {
                calls: CHALLENGES,
                width: CHALLENGE_WIDTH,
            },
            poly_query: framework_hooks::PolyQueryLayout {
                polys: POLYS,
                claims: CLAIMS,
            },
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

        // Building the adapter dry-runs the witness body to discover the step's
        // hook-call counts. That dry run is structure-only, so it needs no cycle
        // parameters — which is what lets registration happen here, before
        // `finalize` supplies them.
        //
        // Hand-over is immediate: it freezes the circuit's shape, and the shape
        // is settled, because every term of the instance comes from a declared
        // parameter rather than from a maximum over steps still to arrive.
        // `with_capacity` rejects a step that needs more than was declared,
        // naming both numbers, at the moment that step registers.
        self.native_registry = self.native_registry.register_circuit(MultiStage::new(
            Adapter::<C, S, R, HEADER_SIZE>::new(step, None, Self::challenge_width())?
                .with_capacity(Self::capacity())?,
        ))?;
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
            Self::challenge_width(),
        )?;
        let trivial = Adapter::<C, _, R, HEADER_SIZE>::new(
            step::internal::trivial::Trivial::new(),
            Some(params),
            Self::challenge_width(),
        )?;
        // The application's slot capacity. Uniform across one application,
        // because the internal circuits read a child's instance as a
        // fixed-width record and any step's proof may be any fuse's child.
        //
        // The *slot counts* are discovered, never declared: an application whose
        // steps open two polynomials pays for two, and the cost of a heavy step
        // falls on the application that registers it rather than on the
        // framework. The challenge input width is the exception, below.
        let capacity = Self::capacity();

        let (total_circuits, log2_circuits) = internal::native::total_circuit_counts(
            self.num_application_steps,
            internal::native::InternalCircuitIndex::NUM,
        );

        // Build the native registry:
        // 1. Application circuits (registered just above)
        // 2. Internal circuits and masks
        // 3. Internal steps
        //
        // Internal circuits are built for the one settled capacity, since
        // every application circuit exposes exactly it.
        //
        // First, register internal circuits and masks
        self.native_registry = internal::native::register_all::<C, R, HEADER_SIZE>(
            self.native_registry,
            params,
            log2_circuits,
            capacity,
        )?;

        // Then, register internal steps
        self.native_registry = self
            .native_registry
            .register_internal_step(MultiStage::new(rerandomize.with_capacity(capacity)?))?;
        self.native_registry = self
            .native_registry
            .register_internal_step(MultiStage::new(trivial.with_capacity(capacity)?))?;

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
        self.nested_registry =
            internal::nested::register_all::<C, R>(self.nested_registry, capacity)?;

        Ok(Application {
            native_registry: self.native_registry.finalize()?,
            nested_registry: self.nested_registry.finalize()?,
            params,
            num_application_steps: self.num_application_steps,
            capacity,
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
    /// The application's settled slot capacity: the pointwise maximum over
    /// its registered steps' discovered plans, folded by
    /// [`ApplicationBuilder::finalize`].
    ///
    /// Every application circuit exposes exactly these slots, so this is the
    /// shape the internal circuits are built for, the shape a proof's lists
    /// have, and the shape padding fills to.
    capacity: framework_hooks::HookLayout,
    /// Cached seeded trivial proof for rerandomization.
    seeded_trivial: OnceCell<Proof<C, R>>,
    /// Test-only: skip the prover-side poly-query pre-check. See
    /// [`ApplicationBuilder::skip_claim_precheck_for_testing`].
    #[cfg(feature = "unstable-fuzzing")]
    pub(crate) skip_claim_precheck: bool,
    _marker: PhantomData<[(); HEADER_SIZE]>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// The application's settled slot capacity — the shape every application
    /// circuit's instance has, and every proof's slot lists.
    pub(crate) fn capacity(&self) -> framework_hooks::HookLayout {
        self.capacity
    }

    /// The nested bridge chain's value-level geometry at this application's
    /// capacity. See [`native_chain_layouts`](Self::native_chain_layouts) for
    /// why a stage's position cannot come from its type.
    pub(crate) fn nested_chain_layout(&self) -> ragu_circuits::staging::InducedStages {
        internal::nested::chain_layout::<C::HostCurve, R>(
            self.capacity,
            self.capacity,
            self.capacity,
        )
    }

    /// The native fuse chains' value-level geometry at this application's
    /// capacity — `(query_chain, error_chain)`.
    ///
    /// Every native stage rx a fuse builds is placed through these rather than
    /// through the typed `Stage::skip_gates()`, which derives its offsets from
    /// `values()` and so from the placeholder shape. Where a stage sits
    /// depends on how wide the stages before it are, and that is a property of
    /// the application, not of a Rust type.
    pub(crate) fn native_chain_layouts(
        &self,
    ) -> (
        ragu_circuits::staging::InducedStages,
        ragu_circuits::staging::InducedStages,
    ) {
        internal::native::chain_layouts::<C, R, HEADER_SIZE>(
            internal::native::InternalCircuitIndex::NUM,
            self.capacity,
            self.capacity,
        )
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
