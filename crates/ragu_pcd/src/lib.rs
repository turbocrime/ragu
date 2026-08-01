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
//! How many polynomials a step may witness, how many openings it may
//! enforce, and how many challenges it may derive (and how wide) are
//! parameters of [`ApplicationBuilder`], so a step's cost falls on the
//! application that registers it. They are declared rather than folded from
//! the registered steps because handing a circuit to the registry freezes
//! its shape, which a maximum over steps would not settle until the last one
//! arrives. A capacity is uniform within one application because the
//! internal circuits read a child's instance as a fixed-width record;
//! steps that use fewer slots are padded up, at a cost that does not grow
//! with the capacity. If a combination does not fit, `finalize` returns
//! [`GateBoundExceeded`](ragu_core::Error::GateBoundExceeded).

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
pub mod step;
mod verify;

use alloc::collections::BTreeMap;
use core::{any::TypeId, cell::OnceCell, marker::PhantomData};

use framework_hooks::HookConfig;
use header::Header;
pub use poly_commitment::{PolyCommitment, PolyHandle};
pub use proof::{Pcd, Proof};
use ragu_arithmetic::{CryptoRngCore, Cycle};
use ragu_circuits::{
    polynomials::Rank,
    registry::{Registry, RegistryBuilder},
    staging::MultiStage,
};
use ragu_core::{Error, Result};
use ragu_primitives::vec::{ConstLen, Len};
use step::{Step, internal::adapter::Adapter};

/// Domain separation tag for Ragu PCD protocol.
// FIXME: choose a permanent domain separation tag before release.
pub(crate) const RAGU_TAG: &[u8] = b"FIXME";

/// The usual way to declare an application's hook capacity:
///
/// ```rust
/// use ragu_circuits::polynomials::ProductionRank;
/// use ragu_pasta::Pasta;
/// use ragu_pcd::{AppHooks, Application};
///
/// type MyApp<'params> = Application<'params, Pasta, ProductionRank, 4, AppHooks<3, 3, 1, 6>>;
/// ```
pub struct AppHooks<
    const POLYS: usize,
    const QUERIES: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
>;

/// Convenience alias for an application that does not use hooks.
pub type NoHooks = AppHooks<0, 0, 0, 0>;

impl<const PW: usize, const PQ: usize, const CD: usize, const CW: usize> HookConfig
    for AppHooks<PW, PQ, CD, CW>
{
    type PolyWitnesses = ConstLen<PW>;
    type PolyQueries = ConstLen<PQ>;

    type ChallengeDerivations = ConstLen<CD>;
    type ChallengeWidth = ConstLen<CW>;
}

/// Builder for an [`Application`] for proof-carrying data.
///
/// An application declares its capacity as two parameters: `HEADER_SIZE`,
/// the width of one encoded header, and `J`, the hook capacities as one
/// type — usually written inline as [`AppHooks`]. Together they are the
/// whole of an application circuit's instance width:
///
/// ```text
/// 3·HEADER_SIZE + 2·POLYS + 4·QUERIES + CHALLENGES·(CHALLENGE_WIDTH + 1)
/// ```
///
/// See [`framework_hooks::HookConfig`] for what each hook number prices;
/// the crate docs say why capacity is declared.
pub struct ApplicationBuilder<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig> {
    native_registry: RegistryBuilder<'params, C::CircuitField, R>,
    nested_registry: RegistryBuilder<'params, C::ScalarField, R>,
    num_application_steps: usize,
    header_map: BTreeMap<header::Suffix, TypeId>,
    /// Test-only: see [`ApplicationBuilder::skip_claim_precheck_for_testing`].
    #[cfg(feature = "unstable-fuzzing")]
    skip_claim_precheck: bool,
    _marker: PhantomData<(J, [(); HEADER_SIZE])>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig> Default
    for ApplicationBuilder<'_, C, R, HEADER_SIZE, J>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig>
    ApplicationBuilder<'params, C, R, HEADER_SIZE, J>
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

        // Building the adapter needs no cycle parameters, so registration
        // happens here, before `finalize` supplies them. Hand-over freezes
        // the circuit's shape, which is settled: every term of the instance
        // comes from a declared parameter.
        self.native_registry =
            self.native_registry
                .register_circuit(MultiStage::new(Adapter::<C, S, R, HEADER_SIZE, J>::new(
                    step,
                )))?;
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
    ) -> Result<Application<'params, C, R, HEADER_SIZE, J>> {
        // The internal steps are built at the application's declared
        // capacity, like its own.
        let rerandomize = Adapter::<C, _, R, HEADER_SIZE, J>::new(
            step::internal::rerandomize::Rerandomize::<()>::new(),
        );
        let trivial =
            Adapter::<C, _, R, HEADER_SIZE, J>::new(step::internal::trivial::Trivial::new());

        let (total_circuits, log2_circuits) =
            internal::native::total_circuit_counts(self.num_application_steps);

        // Native registry order: application circuits (registered above),
        // then internal circuits and masks, then internal steps.
        self.native_registry = internal::native::register_all::<C, R, HEADER_SIZE, J>(
            self.native_registry,
            params,
            log2_circuits,
        )?;

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

        // The nested side needs exactly one number, the poly-slot count —
        // as a value for the layouts and as a `Len` for the gadgets.
        self.nested_registry = internal::nested::register_all::<C, R, J::PolyWitnesses>(
            self.nested_registry,
            J::PolyWitnesses::len(),
        )?;

        Ok(Application {
            native_registry: self.native_registry.finalize()?,
            nested_registry: self.nested_registry.finalize()?,
            params,
            padding: internal::challenge::Padding::new(params, J::ChallengeWidth::len())?,
            num_application_steps: self.num_application_steps,
            seeded_trivial: OnceCell::new(),
            #[cfg(feature = "unstable-fuzzing")]
            skip_claim_precheck: self.skip_claim_precheck,
            _marker: PhantomData,
        })
    }

    /// Disables the fuse-time poly-query pre-check, modelling a malicious
    /// prover who simply does not run it — the pre-check carries no soundness
    /// weight, so tests can see what the *circuits* enforce.
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
pub struct Application<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig> {
    native_registry: Registry<'params, C::CircuitField, R>,
    nested_registry: Registry<'params, C::ScalarField, R>,
    params: &'params C::Params,
    /// The padding constants for unused hook slots, computed once at
    /// [`finalize`](ApplicationBuilder::finalize).
    padding: internal::challenge::Padding<C>,
    num_application_steps: usize,
    /// Cached seeded trivial proof for rerandomization.
    seeded_trivial: OnceCell<Proof<C, R>>,
    /// Test-only: skip the prover-side poly-query pre-check. See
    /// [`ApplicationBuilder::skip_claim_precheck_for_testing`].
    #[cfg(feature = "unstable-fuzzing")]
    pub(crate) skip_claim_precheck: bool,
    _marker: PhantomData<(J, [(); HEADER_SIZE])>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig>
    Application<'_, C, R, HEADER_SIZE, J>
{
    /// The application's settled slot capacity, read off the type parameter
    /// so there is no second representation to keep in step.
    pub(crate) fn hook_layout(&self) -> framework_hooks::HookLayout {
        J::layout()
    }

    /// The nested bridge chain's value-level geometry at this application's
    /// capacity.
    pub(crate) fn nested_chain_layout(&self) -> ragu_circuits::staging::InducedStages {
        internal::nested::NestedLayouts::chain_layout::<C::HostCurve, R>(J::PolyWitnesses::len())
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

    /// The cycle parameters this application was finalized against — where a
    /// caller constructing a
    /// [`derive_challenge`](step::StepCtx::derive_challenge)-calling step
    /// gets them.
    pub fn params(&self) -> &C::Params {
        self.params
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

    /// Commits to a `CircuitField` polynomial — an unblinded Pedersen
    /// commitment on the host curve, bundled with the polynomial and the
    /// commitment's canonically embedded affine coordinates
    /// ([`PolyCommitment::coords`]). Thread the result into a step's witness
    /// for [`StepCtx::witness_polynomial`](step::StepCtx::witness_polynomial).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`] if the commitment is the identity
    /// (e.g. the zero polynomial) or has a coordinate at or above $2^{254}$
    /// — neither has a canonical representation; both are answered by
    /// re-blinding the polynomial.
    pub fn commit_polynomial(
        &self,
        polynomial: &ragu_circuits::polynomials::sparse::Polynomial<C::CircuitField, R>,
    ) -> Result<PolyCommitment<C>> {
        let host = PolyCommitment::<C>::host_commitment(self.params, polynomial)?;
        PolyCommitment::new(polynomial.iter_coeffs().collect(), host)
    }
}
