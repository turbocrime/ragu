//! Framework-side state surfaced to [`Step::witness`](crate::step::Step::witness) impls.
//!
//! [`FrameworkHooks`] bundles the framework's hook-specific state that a step
//! body interacts with through [`StepCtx`](crate::step::StepCtx). It carries two
//! hooks:
//!
//! * [`enforce_polynomial_query`](FrameworkHooks::enforce_polynomial_query) — a
//!   polynomial-query claim sink: steps that need to verify a
//!   polynomial-commitment opening — i.e. that the polynomial committed to by
//!   `com` evaluates to `y` at point `x` — reach it via
//!   [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query),
//!   which delegates here. Each claim carries the opened polynomial's
//!   coefficients so the framework can fold it into the [PCS aggregation].
//!   Every application circuit exposes exactly
//!   [`NUM_POLY_QUERY_SLOTS`] claim slots as part
//!   of its public instance (unused slots hold the canonical padding claim),
//!   binding the claim wires — the commitment point and the $(x, y)$ opening —
//!   to the circuit's $k(Y)$ polynomial. The claims a proof raises are then
//!   *recursively enforced at the next fuse*: the parent folds the quotient
//!   $(p(X) - y)/(X - x)$ into $f(X)$, beta-accumulates $p(X)$ into the PCS
//!   $(P, u, v)$ accumulator, and the `compute_v` circuit re-derives the
//!   matching terms from the instance-bound claim data. The fuse that raises a
//!   claim additionally pre-checks it natively so an honest prover with a bad
//!   witness fails early with [`Error::InvalidWitness`] instead of producing a
//!   proof its parent cannot fuse.
//!
//! * challenge slots — the bookkeeping behind
//!   [`StepCtx::derive_challenge`](crate::step::StepCtx::derive_challenge):
//!   the slot cap, the determinism guard, and the
//!   `(bridged stage commitment, challenge)` pairs the adapter writes into the
//!   application circuit's public instance. Every application circuit gets at
//!   most [`NUM_CHALLENGE_SLOTS`] slots, each
//!   committing at most [`CHALLENGE_WIDTH`](crate::CHALLENGE_WIDTH) elements.
//!
//!   The derivation itself lives on [`StepCtx`](crate::step::StepCtx), not
//!   here, because it needs the rank — to build the slot's stage polynomial —
//!   which this container deliberately does not carry, so that `R` stays out of
//!   every `Step::witness` signature. The values it derives *from* — the cycle
//!   parameters and the proof's blinds — are framework state, so they live here
//!   as [`ProofValues`].
//!
//! ## Structure discovery
//!
//! How many times a step body calls each hook is part of the circuit's
//! structure, so it must be witness-independent. The adapter dry-runs the step
//! body once at registration time (with an [`Empty`](ragu_core::maybe::Empty)
//! witness, on a counting emulator) with a container created by
//! [`new`](FrameworkHooks::new) (**discovery mode**), recording the
//! `derive_challenge` call count and the poly-query claim count. Real synthesis
//! goes through [`with_expected`](FrameworkHooks::with_expected), which replays
//! the discovered count as a per-call determinism guard: a body whose call
//! sequence diverges from the dry run fails with [`Error::InvalidWitness`]
//! instead of silently synthesizing a different circuit.
//!
//! The *width* of each challenge input is not discovered at all — it is
//! [`ChallengeInput::ELEMENTS`], a compile-time constant of the input's type,
//! bounded by `CHALLENGE_WIDTH` with a compile-time assertion. That is why no
//! `ChallengeInput` impl exists for slices or `Vec`s: a runtime length cannot
//! be circuit structure. Data of runtime length must be hashed down to one
//! binding [`Element`] first.
//!
//! ## Challenge soundness
//!
//! A challenge is the hash of a commitment to the values it is derived from —
//! computed natively, witnessed, and re-derived by the parent from the same
//! instance-bound commitment. On a value-carrying driver the returned `Element`
//! holds the real value immediately, so the step body can use it at once.
//!
//! The binding is enforced, in four links:
//!
//! 1. Both halves of the `(point, challenge)` pair are written into the child's
//!    application $k(Y)$ (by the internal `preamble` stage's `application_ky`),
//!    binding them to its committed application rx.
//! 2. The slot's stage polynomial is summed into the application circuit's
//!    claim (in `native::claims`, as `ComputeVCircuit` treats `Query` and
//!    `Eval`), folded in `_10_p`, and mask-registered so the trace split is
//!    unique — so the stage's wires, which `derive_challenge` pins to the
//!    caller's elements, are covered by the circuit check.
//! 3. `point` is the bridge image of that stage's host commitment, tied in the
//!    `loading` circuit against the eval-stage record and in `copying` against
//!    the child's own.
//! 4. `challenge = Hash(point)` is re-derived per `(child, slot)` by the
//!    internal `challenge_binding` circuit, and natively by
//!    [`Application::verify`](crate::Application::verify) for a root proof's own
//!    slots, which no parent has bound yet.
//!
//! Together: the prover cannot choose a challenge independently of the inputs
//! it committed. What remains is the framework-wide deferred PCS opening —
//! the commitment-to-carried-polynomial link that **no** commitment in the
//! system has yet, `bridge_f` and the endoscaling commitments included — so
//! the chain reaches exactly the same parity as the framework's own bridges
//! and no further. `Application::verify` closes it for a root proof's own
//! claims and challenges; interior nodes inherit the framework's status quo.
//! The acceptance gate for that work is
//! `poly_query_com_is_not_bound_to_the_folded_polynomial` in
//! `tests/recursive_claims.rs`.
//!
//! The framework collects the resulting outputs through the adapter's `Aux` for
//! later fuse-time processing. New framework hooks (e.g. transcript threading)
//! belong on this type as well.
//!
//! [PCS aggregation]: https://tachyon.z.cash/ragu/protocol/core/accumulation/pcs.html#pcs-aggregation
//! [`Error::InvalidWitness`]: ragu_core::Error::InvalidWitness

use alloc::vec::Vec;

use ragu_arithmetic::{CurveAffine, Cycle, ff::Field};
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    maybe::{Maybe, MaybeKind},
};
use ragu_primitives::{
    Element, GadgetExt, Point,
    allocator::Standard,
    vec::{ConstLen, FixedVec},
};

use crate::{
    NUM_CHALLENGE_SLOTS, NUM_POLY_QUERY_SLOTS, step::internal::challenge_stage::ChallengeSlots,
};

/// A single polynomial-commitment opening claim, with the polynomial it opens.
///
/// The framework needs the polynomial's coefficients (not just the claim
/// instance) so it can check the claim at fuse time — and, in the future,
/// batch it into the proof system's $(P, u, v)$ accumulator.
pub struct PolyQueryClaim<F: Field, C: CurveAffine<Base = F>> {
    /// The claimed commitment to the polynomial — the nested-curve point the
    /// step witnessed in-circuit. Must equal the framework's commitment to
    /// [`coefficients`](Self::coefficients); see
    /// [`Application::commit_polynomial`](crate::Application::commit_polynomial).
    pub com: C,
    /// Point at which the polynomial is opened.
    pub x: F,
    /// Claimed evaluation $p(x) = y$.
    pub y: F,
    /// Coefficients of the polynomial $p(X)$ being opened, little-endian
    /// (`coefficients[i]` is the coefficient of $X^i$).
    pub coefficients: Vec<F>,
}

/// The in-circuit wires of a derived challenge: the bridged commitment to the
/// slot's stage, and the challenge hashed from it. Both go into the application
/// circuit's public instance so the parent can re-derive one from the other.
pub struct ChallengeWires<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// The slot's stage commitment, bridged onto the nested curve.
    pub point: Point<'dr, D, C>,
    /// The challenge, hashed from [`point`](Self::point).
    pub challenge: Element<'dr, D>,
}

/// The in-circuit wires of a single poly-query claim, retained so the adapter
/// can write them into the application circuit's public instance (binding them
/// to the circuit's $k(Y)$), alongside the witness-only coefficient values the
/// fuse needs for the PCS folding.
pub struct ClaimWires<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// The claimed nested-curve commitment point, as witnessed by the step.
    pub com: Point<'dr, D, C>,
    /// The opening point.
    pub x: Element<'dr, D>,
    /// The claimed evaluation.
    pub y: Element<'dr, D>,
    /// The opened polynomial's coefficient values (witness-only; never wires).
    pub coefficients: DriverValue<D, Vec<D::F>>,
}

/// An input to [`derive_challenge`](crate::step::StepCtx::derive_challenge): a
/// bundle of in-circuit data exposed as a canonical sequence of [`Element`]s.
/// Exactly this sequence is pinned into the slot's challenge stage, whose
/// commitment the challenge is hashed from — so the challenge is bound to this
/// input and nothing else.
///
/// Implemented for [`Element`], [`Point`], and fixed-width compositions of
/// these (tuples, arrays, and references). Deliberately **not** implemented for
/// slices, `Vec`s, or anything else whose length is a runtime value — see
/// [`ELEMENTS`](Self::ELEMENTS).
pub trait ChallengeInput<'dr, D: Driver<'dr>> {
    /// The number of elements [`append_elements`](Self::append_elements)
    /// produces.
    ///
    /// A compile-time constant, because the challenge derivation is circuit
    /// structure: it fixes how many of the slot's stage wires the input
    /// occupies, and the rest are pinned to zero. A runtime-length input would
    /// make the circuit's shape depend on its witness, which the framework
    /// forbids. This is what makes
    /// [`CHALLENGE_WIDTH`](crate::CHALLENGE_WIDTH) a compile-time bound rather
    /// than a runtime check.
    const ELEMENTS: usize;

    /// Appends this input's elements, in canonical order. Must append exactly
    /// [`ELEMENTS`](Self::ELEMENTS) of them; `derive_challenge` checks this.
    fn append_elements(&self, dr: &mut D, out: &mut Vec<Element<'dr, D>>) -> Result<()>;
}

impl<'dr, D: Driver<'dr>> ChallengeInput<'dr, D> for Element<'dr, D> {
    const ELEMENTS: usize = 1;

    fn append_elements(&self, _dr: &mut D, out: &mut Vec<Element<'dr, D>>) -> Result<()> {
        out.push(self.clone());
        Ok(())
    }
}

/// Collects the elements a [`Write`](ragu_primitives::io::Write) gadget
/// serializes into.
struct ElementCollector<'dr, D: Driver<'dr>>(Vec<Element<'dr, D>>);

impl<'dr, D: Driver<'dr>> ragu_primitives::io::Buffer<'dr, D> for ElementCollector<'dr, D> {
    fn write(&mut self, _dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        self.0.push(value.clone());
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> ChallengeInput<'dr, D> for Point<'dr, D, C> {
    const ELEMENTS: usize = 2;

    fn append_elements(&self, dr: &mut D, out: &mut Vec<Element<'dr, D>>) -> Result<()> {
        // Serialize the point's (x, y) coordinate elements via its `Write`
        // impl.
        let mut collector = ElementCollector(Vec::new());
        GadgetExt::write(self, dr, &mut collector)?;
        out.append(&mut collector.0);
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>, T: ChallengeInput<'dr, D>> ChallengeInput<'dr, D> for &T {
    const ELEMENTS: usize = T::ELEMENTS;

    fn append_elements(&self, dr: &mut D, out: &mut Vec<Element<'dr, D>>) -> Result<()> {
        (*self).append_elements(dr, out)
    }
}

impl<'dr, D: Driver<'dr>, T: ChallengeInput<'dr, D>, const N: usize> ChallengeInput<'dr, D>
    for [T; N]
{
    const ELEMENTS: usize = T::ELEMENTS * N;

    fn append_elements(&self, dr: &mut D, out: &mut Vec<Element<'dr, D>>) -> Result<()> {
        for item in self {
            item.append_elements(dr, out)?;
        }
        Ok(())
    }
}

// No impls for `&[T]` or `Vec<T>`: their lengths are runtime values, so they
// cannot supply a compile-time `ELEMENTS`. Hash such data down to a single
// binding `Element` and derive the challenge from that.

macro_rules! impl_challenge_input_tuple {
    ($($name:ident),+) => {
        impl<'dr, D: Driver<'dr>, $($name: ChallengeInput<'dr, D>),+> ChallengeInput<'dr, D>
            for ($($name,)+)
        {
            const ELEMENTS: usize = 0 $(+ $name::ELEMENTS)+;

            fn append_elements(&self, dr: &mut D, out: &mut Vec<Element<'dr, D>>) -> Result<()> {
                #[allow(non_snake_case)]
                let ($($name,)+) = self;
                $($name.append_elements(dr, out)?;)+
                Ok(())
            }
        }
    };
}

impl_challenge_input_tuple!(A);
impl_challenge_input_tuple!(A, B);
impl_challenge_input_tuple!(A, B, C2);
impl_challenge_input_tuple!(A, B, C2, D2);

/// Container for framework-side state threaded through a
/// [`Step::witness`](crate::step::Step::witness) invocation.
///
/// Holds the polynomial-commitment opening-claim sink and the record of
/// [`derive_challenge`](crate::step::StepCtx::derive_challenge) calls. The framework's adapter
/// constructs this, passes it to the step, then surfaces
/// [`into_outputs`](Self::into_outputs) through its `Aux` for later fuse-time
/// processing.
pub struct FrameworkHooks<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    poly_query_claims: Vec<ClaimWires<'dr, D, C::NestedCurve>>,
    /// Number of polynomials witnessed so far via
    /// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial).
    /// Assigns each claim its slot, which fixes the bridge stage — and
    /// therefore the generator positions — its `com` commits to.
    witnessed_claims: usize,
    /// The `(bridged stage commitment, challenge)` pair each
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge) call produced, in slot
    /// order.
    challenge_pairs: Vec<ChallengeWires<'dr, D, C::NestedCurve>>,
    /// The values each challenge stage commits, in slot order.
    challenge_inputs: Vec<DriverValue<D, [D::F; crate::CHALLENGE_WIDTH]>>,
    /// Number of [`derive_challenge`](crate::step::StepCtx::derive_challenge) calls so far.
    /// Each occupies one of the
    /// [`NUM_CHALLENGE_SLOTS`] slots; the widths
    /// need no recording, being compile-time constants of the input types.
    challenge_calls: usize,
    /// The hook-call counts discovered by the registration-time dry run,
    /// replayed as determinism guards. `None` in discovery mode, which is the
    /// pass that establishes them (see the [module documentation](self)).
    ///
    /// An `Option`, not a [`DriverValue`] like [`proof_values`](Self::proof_values):
    /// the dry run and keygen are *both* structure-only, so this absence is not
    /// the driver's.
    expected: Option<HookLayout>,
    /// The proof-level values the hooks commit to. See [`ProofValues`].
    proof_values: DriverValue<D, ProofValues<'dr, C>>,
}

/// Every hook's output as plain values, for the fuse.
///
/// The value-level counterpart of [`FrameworkHookOutputs`], which holds
/// in-circuit wires. A step circuit's `Aux` carries one of these beside the
/// step's own `Aux`, so the framework's contribution stays one named thing
/// rather than a handful of sibling fields — and so adding a hook means adding
/// a field here, which the compiler then forces every reader to acknowledge.
pub struct FrameworkAux<C: Cycle> {
    /// The step's poly-query claims, padded to exactly [`NUM_POLY_QUERY_SLOTS`]
    /// entries, in slot order — matching the instance layout the circuit
    /// committed to. Each carries the opened polynomial's coefficients; fuse
    /// pre-checks every claim natively, persists the claim instances in the
    /// proof, and the *next* fuse enforces them recursively via the PCS
    /// accumulator.
    pub claims:
        FixedVec<PolyQueryClaim<C::CircuitField, C::NestedCurve>, ConstLen<NUM_POLY_QUERY_SLOTS>>,
    /// The derived-challenge pairs the circuit exposes, padded to exactly
    /// [`NUM_CHALLENGE_SLOTS`] entries, in slot order.
    pub challenges: FixedVec<
        crate::proof::ChallengeOpening<C::NestedCurve, C::CircuitField>,
        ConstLen<NUM_CHALLENGE_SLOTS>,
    >,
    /// The values each challenge stage commits, in slot order, zero-padded to
    /// [`CHALLENGE_WIDTH`](crate::CHALLENGE_WIDTH). Plain field elements: the
    /// fuse holds the rank, so it builds the stage polynomials itself.
    pub challenge_inputs:
        FixedVec<[C::CircuitField; crate::CHALLENGE_WIDTH], ConstLen<NUM_CHALLENGE_SLOTS>>,
}

/// Transposes a list of per-item driver values into one driver value holding
/// the list, in order.
///
/// The values are taken inside a single `try_just`, so on structure-only
/// drivers the closure never runs (`Empty::try_just` discards it) and no
/// `take` is attempted.
fn collect_values<'dr, D: Driver<'dr>, T: Send>(
    values: Vec<DriverValue<D, T>>,
) -> Result<DriverValue<D, Vec<T>>> {
    D::try_just(move || Ok(values.into_iter().map(Maybe::take).collect()))
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> FrameworkHookOutputs<'dr, D, C> {
    /// Reads each hook's wires back out as plain values, for the fuse.
    pub(crate) fn into_values(self) -> Result<DriverValue<D, FrameworkAux<C>>> {
        let mut claims = Vec::with_capacity(self.poly_query_claims.len());
        for ClaimWires {
            com,
            x,
            y,
            coefficients,
        } in self.poly_query_claims
        {
            claims.push(D::try_just(|| {
                Ok(PolyQueryClaim {
                    com: com.value().take(),
                    x: *x.value().take(),
                    y: *y.value().take(),
                    coefficients: coefficients.take(),
                })
            })?);
        }
        let claims = collect_values::<D, _>(claims)?;

        let mut challenges = Vec::with_capacity(self.challenge_pairs.len());
        for pair in self.challenge_pairs {
            challenges.push(D::try_just(|| {
                Ok(crate::proof::ChallengeOpening {
                    point: pair.point.value().take(),
                    challenge: *pair.challenge.value().take(),
                })
            })?);
        }
        let challenges = collect_values::<D, _>(challenges)?;
        let challenge_inputs = collect_values::<D, _>(self.challenge_inputs)?;

        // `finish` padded each to its slot count, so these conversions cannot
        // fail; the fixed types are what make that guarantee readable at every
        // consumer, instead of a length assertion at each one.
        D::try_just(move || {
            Ok(FrameworkAux {
                claims: FixedVec::try_from(claims.take())?,
                challenges: FixedVec::try_from(challenges.take())?,
                challenge_inputs: FixedVec::try_from(challenge_inputs.take())?,
            })
        })
    }
}

/// The hook-call counts a step body's circuit structure commits to.
///
/// Discovered by the registration-time dry run and replayed at synthesis: a
/// body whose calls diverge from it would synthesize a circuit other than the
/// one that was registered.
#[derive(Clone, Copy)]
pub struct HookLayout {
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge) calls.
    pub challenge_calls: usize,
    /// [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) claims.
    pub claims: usize,
}

/// The proof's two blind sources, as the step circuit's witness carries them.
///
/// Separate from the cycle parameters on purpose. Both are absent during
/// registration, but for different reasons: the parameters do not exist until
/// [`ApplicationBuilder::finalize`](crate::ApplicationBuilder::finalize),
/// while the blinds do not exist until a *proof* is being built. Only the
/// second is an execution-mode difference, so only the second rides a
/// [`DriverValue`] — and being plain field elements with no lifetime, they do
/// so with none of the variance or outlives obligations a borrowed parameter
/// would impose on the step circuit's `Witness`.
pub struct Alphas<C: Cycle> {
    /// Blinds the nested bridge stages.
    pub bridge: C::ScalarField,
    /// Blinds the application circuit's challenge stages.
    pub challenge: C::CircuitField,
}

// Hand-written: `derive` would demand `C: Clone`/`C: Copy`, but both fields are
// field elements, `Copy` for every `Cycle`.
impl<C: Cycle> Clone for Alphas<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: Cycle> Copy for Alphas<C> {}

/// The proof-level values a hook needs to compute a witness: the cycle
/// parameters, and the proof's two blind sources.
///
/// A [`DriverValue`] rather than an `Option`, because its absence is exactly
/// the driver's absence of values — unlike [`HookLayout`], which
/// distinguishes two passes that are *both* structure-only. Every use already
/// sits inside a `try_just` that a structure-only driver discards, so there is
/// no absent case to handle and no error to invent for a state that cannot
/// arise: registration builds its adapter with `Adapter::new` and only ever
/// witnesses it on a structure-only driver, while proving builds it with
/// `Adapter::proving`. Those two facts meet once, in `Adapter::witness`.
pub struct ProofValues<'dr, C: Cycle> {
    pub(crate) params: &'dr C::Params,
    pub(crate) bridge_alpha: C::ScalarField,
    pub(crate) challenge_alpha: C::CircuitField,
}

impl<'dr, C: Cycle> ProofValues<'dr, C> {
    pub(crate) fn new(
        params: &'dr C::Params,
        bridge_alpha: C::ScalarField,
        challenge_alpha: C::CircuitField,
    ) -> Self {
        Self {
            params,
            bridge_alpha,
            challenge_alpha,
        }
    }
}

// Hand-written: `derive` would demand `C: Clone`/`C: Copy`, but the fields are
// a shared reference and two field elements, all `Copy` for every `Cycle`.
impl<C: Cycle> Clone for ProofValues<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: Cycle> Copy for ProofValues<'_, C> {}

/// Aggregate of every hook's accumulated output, returned by
/// [`FrameworkHooks::into_outputs`]. Adding a new hook means adding a field
/// here, which forces every drain site to acknowledge it.
pub struct FrameworkHookOutputs<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    /// Polynomial-commitment opening claims raised via
    /// [`FrameworkHooks::enforce_polynomial_query`], in call order — the
    /// in-circuit wires plus the witness-only coefficient values.
    pub poly_query_claims: Vec<ClaimWires<'dr, D, C::NestedCurve>>,
    /// Number of [`StepCtx::derive_challenge`](crate::step::StepCtx::derive_challenge) calls. The
    /// registration-time dry run reads this to discover the call count; the
    /// adapter compares it against that count after real synthesis.
    pub challenge_calls: usize,
    /// The `(bridged commitment, challenge)` pair per `derive_challenge` call,
    /// in slot order.
    pub challenge_pairs: Vec<ChallengeWires<'dr, D, C::NestedCurve>>,
    /// The values each challenge stage commits, in slot order.
    pub challenge_inputs: Vec<DriverValue<D, [D::F; crate::CHALLENGE_WIDTH]>>,
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> FrameworkHooks<'dr, D, C> {
    /// Creates a new, empty hook container in **discovery mode**: no expected
    /// call layout, so [`derive_challenge`](crate::step::StepCtx::derive_challenge)
    /// records calls without checking them, and no proof to draw values from.
    /// Used by the registration-time dry run that discovers the call layout;
    /// real synthesis goes through [`with_expected`](Self::with_expected).
    ///
    /// **Structure-only drivers only**, and enforced as such: [`MaybeKind::empty`]
    /// does not compile on a value-carrying kind, so a discovery container that
    /// reached a real witness pass is a build error rather than a proof whose
    /// challenges came from nothing. That is the guarantee `Maybe` exists to
    /// give. It is also why [`with_expected`](Self::with_expected) spells its
    /// fields out instead of delegating here — the two constructors are for the
    /// two driver kinds, and neither should compile in the other's place.
    pub fn new() -> Self {
        Self {
            poly_query_claims: Vec::new(),
            witnessed_claims: 0,
            challenge_calls: 0,
            challenge_pairs: Vec::new(),
            challenge_inputs: Vec::new(),
            expected: None,
            proof_values: <D::MaybeKind as MaybeKind>::empty(),
        }
    }

    /// Creates a hook container for real synthesis: the `derive_challenge` call
    /// count discovered at registration time, and the proof-level values the
    /// hooks commit. Each
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge) call is
    /// checked against the count, so a body that makes more calls than the dry
    /// run did fails at the offending call.
    ///
    /// See [`new`](Self::new) for why this does not delegate to it.
    pub fn with_expected(
        expected: HookLayout,
        proof_values: DriverValue<D, ProofValues<'dr, C>>,
    ) -> Self {
        Self {
            poly_query_claims: Vec::new(),
            witnessed_claims: 0,
            challenge_calls: 0,
            challenge_pairs: Vec::new(),
            challenge_inputs: Vec::new(),
            expected: Some(expected),
            proof_values,
        }
    }

    /// The proof-level values the hooks commit to, for the hook bodies that
    /// need them.
    pub(crate) fn proof_values(&self) -> DriverValue<D, ProofValues<'dr, C>> {
        Maybe::clone(&self.proof_values)
    }

    /// Assigns the next poly-query claim slot, in `witness_polynomial` call
    /// order. The call sequence is circuit structure (discovered by the
    /// adapter's dry run), so the assignment is deterministic.
    pub(crate) fn next_claim_slot(&mut self) -> Result<usize> {
        let slot = self.witnessed_claims;
        if slot >= crate::NUM_POLY_QUERY_SLOTS {
            return Err(Error::InvalidWitness(
                "step witnessed more polynomials than there are poly-query claim slots".into(),
            ));
        }
        self.witnessed_claims += 1;
        Ok(slot)
    }

    /// Takes the next challenge slot, enforcing both the framework cap and the
    /// discovered call count.
    pub(crate) fn take_challenge_slot(&mut self) -> Result<usize> {
        if self.challenge_calls >= crate::NUM_CHALLENGE_SLOTS {
            return Err(Error::InvalidWitness(
                "step derived more challenges than there are challenge slots".into(),
            ));
        }
        if let Some(expected) = self.expected.map(|l| l.challenge_calls)
            && self.challenge_calls >= expected
        {
            return Err(Error::InvalidWitness(
                "derive_challenge called more times than the discovered call count; \
                 circuit structure must not depend on witness values"
                    .into(),
            ));
        }
        let slot = self.challenge_calls;
        self.challenge_calls += 1;
        Ok(slot)
    }

    /// Records a derived challenge's `(bridged stage commitment, challenge)`
    /// pair. The adapter writes these into the application circuit's public
    /// instance, binding them to its $k(Y)$ so the parent's binding circuit can
    /// re-derive the challenge from the point.
    pub(crate) fn record_challenge(
        &mut self,
        point: Point<'dr, D, C::NestedCurve>,
        challenge: Element<'dr, D>,
        inputs: DriverValue<D, [D::F; crate::CHALLENGE_WIDTH]>,
    ) {
        self.challenge_pairs
            .push(ChallengeWires { point, challenge });
        self.challenge_inputs.push(inputs);
    }

    /// Records a claim that the polynomial with the given `coefficients`
    /// (little-endian), committed to by `com`, evaluates to `y` at the point
    /// `x`.
    ///
    /// The claim wires occupy one of the application circuit's
    /// [`NUM_POLY_QUERY_SLOTS`] instance slots,
    /// binding them to the circuit's $k(Y)$; the claim itself is recursively
    /// enforced at the next fuse via the PCS accumulator. The fuse that raises
    /// it additionally pre-checks it natively (see
    /// [`Application::commit_polynomial`](crate::Application::commit_polynomial));
    /// a dishonest witness aborts with [`Error::InvalidWitness`].
    ///
    /// The number of calls per step body is part of the circuit structure: it
    /// must not depend on witness values and must not exceed
    /// `NUM_POLY_QUERY_SLOTS` (checked by the adapter).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`] if `slot` — the slot assigned when the
    /// polynomial was witnessed, which fixed the bridge stage `com` commits to
    /// — is not the instance slot this claim is about to occupy. The two are
    /// assigned by separate counters, so a body that witnesses `A` then `B` but
    /// enforces `B` then `A` would otherwise write each claim's `com` into the
    /// other's slot. Pair each
    /// [`witness_polynomial`](crate::step::StepCtx::witness_polynomial) with its
    /// [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) in the
    /// same order.
    pub fn enforce_polynomial_query(
        &mut self,
        _dr: &mut D,
        slot: usize,
        com: Point<'dr, D, C::NestedCurve>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
        coefficients: DriverValue<D, Vec<D::F>>,
    ) -> Result<()> {
        if slot != self.poly_query_claims.len() {
            return Err(Error::InvalidWitness(
                "poly-query claims must be enforced in the order their polynomials were \
                 witnessed"
                    .into(),
            ));
        }
        self.poly_query_claims.push(ClaimWires {
            com,
            x,
            y,
            coefficients,
        });
        Ok(())
    }

    /// Completes the fixed-size slot layout and drains the hooks.
    ///
    /// The two determinism guards first: every discovered call must have
    /// happened, or the synthesized circuit would differ from the registered
    /// structure. These complement the per-call checks inside
    /// [`take_challenge_slot`](Self::take_challenge_slot) and
    /// [`next_claim_slot`](Self::next_claim_slot), which catch the excess; this
    /// catches the shortfall.
    ///
    /// Then padding. Every application circuit exposes exactly
    /// [`NUM_POLY_QUERY_SLOTS`] claims and [`NUM_CHALLENGE_SLOTS`] challenge
    /// pairs, whatever the body used, so the instance shape — which the
    /// internal circuits read as a fixed-width record — never depends on the
    /// step. The unused slots are filled with values that are *real*, not
    /// sentinel: a claim that is trivially true, and a challenge honestly
    /// derived from an all-zero stage. Nothing downstream distinguishes them.
    ///
    /// `R` is a method parameter rather than a type parameter so the rank stays
    /// out of this container, and out of every `Step::witness` signature with
    /// it.
    pub(crate) fn finish<R: Rank>(
        mut self,
        dr: &mut D,
        slots: &mut dyn ChallengeSlots<'dr, D, C>,
    ) -> Result<FrameworkHookOutputs<'dr, D, C>> {
        if let Some(expected) = self.expected {
            if self.challenge_calls != expected.challenge_calls {
                return Err(Error::InvalidWitness(
                    "derive_challenge called fewer times than the discovered call count; \
                     circuit structure must not depend on witness values"
                        .into(),
                ));
            }
            if self.poly_query_claims.len() != expected.claims {
                return Err(Error::InvalidWitness(
                    "enforce_poly_query call count diverged from the discovered claim count; \
                     circuit structure must not depend on witness values"
                        .into(),
                ));
            }
        }

        self.pad_claims::<R>(dr)?;
        self.pad_challenges(dr, slots)?;
        Ok(self.into_outputs())
    }

    /// Fills unused poly-query slots with the canonical padding claim.
    ///
    /// The padding is *witnessed*, like a real claim, rather than baked in as a
    /// circuit constant, so an application circuit's identity never depends on
    /// the runtime generators. Each slot's `com` is that slot's bridge stage
    /// commitment, so the padding commitment differs per slot exactly as a real
    /// claim's does.
    fn pad_claims<R: Rank>(&mut self, dr: &mut D) -> Result<()> {
        let allocator = &mut Standard::new();
        while self.poly_query_claims.len() < NUM_POLY_QUERY_SLOTS {
            let slot = self.poly_query_claims.len();
            let proof_values = self.proof_values();
            let padding = D::try_just(move || {
                let proof_values = proof_values.take();
                let (host, x, y) =
                    crate::internal::challenge::padding_claim::<C>(proof_values.params);
                let com = crate::internal::challenge::claim_bridge_commitment::<C, R>(
                    proof_values.params,
                    slot,
                    crate::internal::challenge::claim_bridge_alpha::<C>(
                        proof_values.bridge_alpha,
                        slot,
                    ),
                    host,
                )?;
                Ok((com, x, y))
            })?;

            self.poly_query_claims.push(ClaimWires {
                com: Point::alloc(dr, padding.as_ref().map(|(com, _, _)| *com))?,
                x: Element::alloc(dr, allocator, padding.as_ref().map(|(_, x, _)| *x))?,
                y: Element::alloc(dr, allocator, padding.map(|(_, _, y)| y))?,
                coefficients: D::just(|| alloc::vec![D::F::ONE]),
            });
        }
        Ok(())
    }

    /// Fills unused challenge slots.
    ///
    /// An unused slot is *filled*, not skipped. Its wires are reserved either
    /// way — the stage builder allocates them before the body runs — and an
    /// allocated wire is a free one: the `Coeff::Zero` it is allocated with is
    /// the honest assignment, not a constraint. Leaving the slot's guard
    /// unconsumed would therefore leave [`CHALLENGE_WIDTH`](crate::CHALLENGE_WIDTH)
    /// unconstrained wires inside a region the stage commits, which is exactly
    /// the grinding the challenge stages' wire discipline forbids: a prover
    /// could vary them, and with them the commitment and its challenge.
    ///
    /// So padding runs the same path a used slot does — fill, then pin every
    /// wire — differing only in that all of them are pinned to zero and none to
    /// a caller's element. Deriving the challenge honestly also keeps the
    /// parent's binding circuit uniform: it re-derives every slot without
    /// knowing which ones the step actually used.
    fn pad_challenges(
        &mut self,
        dr: &mut D,
        slots: &mut dyn ChallengeSlots<'dr, D, C>,
    ) -> Result<()> {
        let allocator = &mut Standard::new();
        while self.challenge_pairs.len() < NUM_CHALLENGE_SLOTS {
            let zeros = D::just(|| [D::F::ZERO; crate::CHALLENGE_WIDTH]);
            let filled = slots.fill_next(dr, self.proof_values(), Maybe::clone(&zeros))?;
            for wire in filled.wires.iter() {
                Element::enforce_zero(wire, dr)?;
            }
            self.challenge_pairs.push(ChallengeWires {
                point: Point::alloc(dr, filled.derived.as_ref().map(|(p, _)| *p))?,
                challenge: Element::alloc(dr, allocator, filled.derived.map(|(_, c)| c))?,
            });
            self.challenge_inputs.push(zeros);
        }
        Ok(())
    }

    /// Consumes the container and returns every hook's accumulated output.
    pub fn into_outputs(self) -> FrameworkHookOutputs<'dr, D, C> {
        FrameworkHookOutputs {
            poly_query_claims: self.poly_query_claims,
            challenge_calls: self.challenge_calls,
            challenge_pairs: self.challenge_pairs,
            challenge_inputs: self.challenge_inputs,
        }
    }
}

/// Discovery-mode default; see [`FrameworkHooks::new`], including why this does
/// not compile on a value-carrying driver.
impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> Default for FrameworkHooks<'dr, D, C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::Cycle;
    use ragu_core::{
        drivers::emulator::{Emulator, Wireless},
        maybe::Empty,
    };
    use ragu_pasta::{Fp, Pasta};

    use super::*;

    type NestedCurve = <Pasta as Cycle>::NestedCurve;
    type Dr<'dr> = Emulator<Wireless<Empty, Fp>>;

    /// The framework caps a step body at `NUM_CHALLENGE_SLOTS` challenges.
    #[test]
    fn challenge_slots_are_capped() {
        let mut hooks = FrameworkHooks::<Dr<'_>, Pasta>::new();
        for expected in 0..crate::NUM_CHALLENGE_SLOTS {
            assert_eq!(
                hooks.take_challenge_slot().expect("within the cap"),
                expected
            );
        }
        let error = hooks
            .take_challenge_slot()
            .expect_err("the call past the cap should fail");
        assert!(
            alloc::format!("{error}").contains("challenge slots"),
            "unexpected error: {error}"
        );
    }

    /// A body that derives more challenges than the registration-time dry run
    /// did is rejected, rather than silently synthesizing a larger circuit.
    #[test]
    fn challenge_slots_respect_the_discovered_count() {
        let mut hooks = FrameworkHooks::<Dr<'_>, Pasta>::with_expected(
            HookLayout {
                challenge_calls: 1,
                claims: 0,
            },
            <Empty as MaybeKind>::empty::<ProofValues<'_, Pasta>>(),
        );
        hooks.take_challenge_slot().expect("the discovered call");
        let error = hooks
            .take_challenge_slot()
            .expect_err("an undiscovered call should fail");
        assert!(
            alloc::format!("{error}").contains("discovered call count"),
            "unexpected error: {error}"
        );
    }

    /// The width of a challenge input is a compile-time property of its type.
    #[test]
    fn challenge_input_widths_are_compile_time() {
        const fn width<'dr, G: ChallengeInput<'dr, Dr<'dr>>>() -> usize {
            G::ELEMENTS
        }
        type NestedPoint<'dr> = Point<'dr, Dr<'dr>, NestedCurve>;

        assert_eq!(width::<Element<'_, Dr<'_>>>(), 1);
        assert_eq!(width::<NestedPoint<'_>>(), 2);
        assert_eq!(width::<(Element<'_, Dr<'_>>, NestedPoint<'_>)>(), 3);
        assert_eq!(width::<[NestedPoint<'_>; 2]>(), 4);
        assert!(width::<[NestedPoint<'_>; 2]>() <= crate::CHALLENGE_WIDTH);
    }
}
