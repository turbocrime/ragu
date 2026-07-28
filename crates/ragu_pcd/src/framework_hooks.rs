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
//!   the application's claim capacity in slot form as part
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
//!   the slot cap, the determinism guard, and the `(points, challenge)` records
//!   the adapter writes into the application circuit's public instance. Every
//!   application circuit gets the application's challenge capacity in slots, each
//!   absorbing exactly
//!   [`CHALLENGE_POINTS_PER_CALL`](crate::CHALLENGE_POINTS_PER_CALL) points.
//!
//! ## Structure discovery
//!
//! How many times a step body calls each hook is part of the circuit's
//! structure, so it must be witness-independent. The adapter dry-runs the step
//! body once at registration time (with an [`Empty`](ragu_core::maybe::Empty)
//! witness, on a counting emulator) with a container created by
//! [`new`](FrameworkHooks::new) (**discovery mode**), recording the
//! `derive_challenge` call count and the poly-query claim count. Real synthesis
//! goes through [`with_expected`](FrameworkHooks::with_expected), and its
//! `check_layout` compares what the body actually did against what was
//! discovered, on every axis: a body whose call
//! counts diverge from the dry run fails with [`Error::InvalidWitness`]
//! instead of silently synthesizing a different circuit.
//!
//! How many *points* a call passes is not discovered, and need not be: every
//! slot's instance region holds `CHALLENGE_POINTS_PER_CALL` points, with the
//! positions a call leaves empty filled by a fixed sentinel. So a call's point
//! count is witness data, not structure.
//!
//! ## Challenge soundness
//!
//! A challenge is the hash of the points it was derived from — computed
//! natively, witnessed, and re-derived by the parent from the same
//! instance-bound points. On a value-carrying driver the returned `Element`
//! holds the real value immediately, so the step body can use it at once.
//!
//! The binding is enforced, in two links:
//!
//! 1. The slot's points and its challenge are written into the child's
//!    application $k(Y)$ (by the internal `preamble` stage's `application_ky`),
//!    binding them to its committed application rx.
//! 2. `challenge = Hash(points)` is re-derived per `(child, slot)` by the
//!    internal `challenge_binding` circuit, and natively by
//!    [`Application::verify`](crate::Application::verify) for a root proof's own
//!    slots, which no parent has bound yet.
//!
//! Together: the prover cannot choose a challenge independently of the points
//! it passed. **What those points bind is the caller's responsibility** — the
//! framework binds the challenge to the points, not the points to any
//! particular data. A step passing a freely witnessed point can grind its
//! challenge by varying it, so every point must be one this step has pinned
//! (a poly-query commitment, a header-carried point, or a point otherwise
//! constrained). This is the same discipline the framework applies to itself:
//! compress data into a binding commitment, then derive from that.
//!
//! What remains beyond that is the framework-wide deferred PCS opening — the
//! commitment-to-carried-polynomial link that **no** commitment in the system
//! has yet, `bridge_f` and the endoscaling commitments included — so the chain
//! reaches exactly the same parity as the framework's own bridges and no
//! further. `Application::verify` closes it for a root proof's own claims and
//! challenges; interior nodes inherit the framework's status quo. The
//! acceptance gate for that work is
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
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    maybe::{Maybe, MaybeKind},
};
use ragu_primitives::{Element, Point};

/// A single witnessed polynomial: its commitment and its coefficients.
///
/// The framework needs the coefficients (not just the commitment) so it can
/// check queries at fuse time — and batch the polynomial into the proof
/// system's $(P, u, v)$ accumulator.
pub struct WitnessedPoly<F: Field, C: CurveAffine<Base = F>> {
    /// The claimed commitment to the polynomial — the nested-curve point the
    /// step witnessed in-circuit. Must equal the framework's commitment to
    /// [`coefficients`](Self::coefficients); see
    /// [`Application::commit_polynomial`](crate::Application::commit_polynomial).
    pub com: C,
    /// Coefficients of the polynomial $p(X)$, little-endian
    /// (`coefficients[i]` is the coefficient of $X^i$).
    pub coefficients: Vec<F>,
}

/// A single opening claim: polynomial [`poly_slot`](Self::poly_slot) evaluates
/// to `y` at `x`.
///
/// Several of these may name the same polynomial — that is what makes a repeat
/// opening cheap.
pub struct PolyQueryClaim<F: Field> {
    /// Index of the polynomial being opened, into the step's witnessed
    /// polynomials.
    pub poly_slot: F,
    /// Point at which the polynomial is opened.
    pub x: F,
    /// Claimed evaluation $p(x) = y$.
    pub y: F,
}

/// The in-circuit wires of a derived challenge: the points it was hashed from,
/// and the challenge itself. All of them go into the application circuit's
/// public instance so the parent can re-derive the challenge from the points.
pub struct ChallengeWires<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// The slot's input points, exactly
    /// [`CHALLENGE_POINTS_PER_CALL`](crate::CHALLENGE_POINTS_PER_CALL) of them:
    /// the caller's, then the sentinel in each position left empty.
    pub points: Vec<Point<'dr, D, C>>,
    /// The challenge, hashed from [`points`](Self::points).
    pub challenge: Element<'dr, D>,
}

/// The in-circuit wires of a single witnessed **polynomial**, retained so the
/// adapter can write them into the application circuit's public instance
/// (binding them to the circuit's $k(Y)$), alongside the witness-only
/// coefficient values the fuse needs for the PCS folding.
///
/// One of these per [`witness_polynomial`](crate::step::StepCtx::witness_polynomial)
/// call. `com` lives here rather than on each query precisely because it
/// identifies the polynomial: a query names its polynomial by index, and if it
/// carried its own copy of `com` nothing would force the two to agree — a
/// prover could pair one slot's commitment with another slot's evaluation.
pub struct PolyWires<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// The claimed nested-curve commitment point, as witnessed by the step.
    pub com: Point<'dr, D, C>,
    /// The polynomial's coefficient values (witness-only; never wires).
    pub coefficients: DriverValue<D, Vec<D::F>>,
}

/// The in-circuit wires of a single **query**: which polynomial is opened,
/// where, and to what.
///
/// One of these per [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query)
/// call. Several queries may name the same polynomial — that is the point of
/// the split, and it is why a repeat opening costs only these three elements.
pub struct QueryWires<'dr, D: Driver<'dr>> {
    /// Index of the polynomial being opened, as a constant element.
    ///
    /// Pinned to a constant rather than allocated free: it is circuit
    /// structure (fixed by which handle the body passed), so a prover must not
    /// be able to vary it and re-aim a query at a different polynomial.
    pub poly_slot: Element<'dr, D>,
    /// The opening point.
    pub x: Element<'dr, D>,
    /// The claimed evaluation.
    pub y: Element<'dr, D>,
}

/// Container for framework-side state threaded through a
/// [`Step::witness`](crate::step::Step::witness) invocation.
///
/// Holds the polynomial-commitment opening-claim sink and the record of
/// [`derive_challenge`](crate::step::StepCtx::derive_challenge) calls. The framework's adapter
/// constructs this, passes it to the step, then surfaces
/// [`into_outputs`](Self::into_outputs) through its `Aux` for later fuse-time
/// processing.
pub struct FrameworkHooks<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    /// One entry per [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query)
    /// call, in call order.
    poly_queries: Vec<QueryWires<'dr, D>>,
    /// One entry per
    /// [`witness_polynomial`](crate::step::StepCtx::witness_polynomial) call,
    /// in call order. A polynomial's position here is its slot, which fixes the
    /// bridge stage — and therefore the generator positions — its `com` commits
    /// to, and is what a query names.
    witnessed_polys: Vec<PolyWires<'dr, D, C::NestedCurve>>,
    /// The `(points, challenge)` record each
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge) call
    /// produced, in slot order. Its length *is* the call count — how many
    /// points a call passed needs no recording, every slot holding the same
    /// number.
    challenge_pairs: Vec<ChallengeWires<'dr, D, C::NestedCurve>>,
    /// The hook-call counts discovered by the registration-time dry run,
    /// checked once by [`check_layout`](Self::check_layout). `None` in
    /// discovery mode, which is the pass that establishes them (see the
    /// [module documentation](self)).
    ///
    /// An `Option`, not a [`DriverValue`] like [`proof_values`](Self::proof_values):
    /// the dry run and keygen are *both* structure-only, so this absence is not
    /// the driver's.
    expected: Option<HookLayout>,
    /// The proof-level values the hooks commit to. See [`ProofValues`].
    proof_values: DriverValue<D, ProofValues<'dr, C>>,
    /// The application's slot capacities — the pointwise maximum over every
    /// registered step's discovered plan, settled at
    /// [`finalize`](crate::ApplicationBuilder::finalize).
    ///
    /// Every application circuit exposes exactly this many slots, whatever its
    /// own step used, because the internal circuits read a child's instance as
    /// a fixed-width record. A step that needs fewer pays for the difference
    /// in padding; a step that needs more is rejected here.
    capacity: HookLayout,
}

/// Every hook's output as plain values, for the fuse.
///
/// The value-level counterpart of [`FrameworkHookOutputs`], which holds
/// in-circuit wires. A step circuit's `Aux` carries one of these beside the
/// step's own `Aux`, so the framework's contribution stays one named thing
/// rather than a handful of sibling fields — and so adding a hook means adding
/// a field here, which the compiler then forces every reader to acknowledge.
pub struct FrameworkAux<C: Cycle> {
    /// The step's witnessed polynomials, padded to the application's poly
    /// capacity, in slot order — matching the instance layout the circuit
    /// committed to. Each carries its coefficients, which the fuse folds into
    /// the PCS accumulator.
    pub polys: Vec<WitnessedPoly<C::CircuitField, C::NestedCurve>>,
    /// The step's opening claims, padded to the application's claim capacity,
    /// in call order. Each names one of [`polys`](Self::polys). Fuse
    /// pre-checks every claim natively, persists the claim instances in the
    /// proof, and the *next* fuse enforces them recursively via the PCS
    /// accumulator.
    pub claims: Vec<PolyQueryClaim<C::CircuitField>>,
    /// The derived-challenge records the circuit exposes, padded to the
    /// application's challenge capacity, in slot order.
    pub challenges: Vec<crate::proof::ChallengeOpening<C::NestedCurve, C::CircuitField>>,
}

/// A small non-negative index as a field element.
///
/// Summed from `ONE` rather than converted, so this needs only [`Field`] and
/// the hook container does not have to demand [`PrimeField`] of every driver it
/// is generic over. The indices are slot numbers, bounded by
/// the application's poly capacity, so the loop is a handful of additions — no
/// gates, and nothing that scales.
///
/// [`PrimeField`]: ragu_arithmetic::ff::PrimeField
pub(crate) fn field_index<F: Field>(index: usize) -> F {
    let mut value = F::ZERO;
    for _ in 0..index {
        value += F::ONE;
    }
    value
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
        let mut polys = Vec::with_capacity(self.witnessed_polys.len());
        for PolyWires { com, coefficients } in self.witnessed_polys {
            polys.push(D::try_just(|| {
                Ok(WitnessedPoly {
                    com: com.value().take(),
                    coefficients: coefficients.take(),
                })
            })?);
        }
        let polys = collect_values::<D, _>(polys)?;

        let mut claims = Vec::with_capacity(self.poly_queries.len());
        for QueryWires { poly_slot, x, y } in self.poly_queries {
            claims.push(D::try_just(|| {
                Ok(PolyQueryClaim {
                    poly_slot: *poly_slot.value().take(),
                    x: *x.value().take(),
                    y: *y.value().take(),
                })
            })?);
        }
        let claims = collect_values::<D, _>(claims)?;

        let mut challenges = Vec::with_capacity(self.challenge_pairs.len());
        for pair in self.challenge_pairs {
            challenges.push(D::try_just(|| {
                let mut points = Vec::with_capacity(pair.points.len());
                for point in &pair.points {
                    points.push(point.value().take());
                }
                Ok(crate::proof::ChallengeOpening {
                    points,
                    challenge: *pair.challenge.value().take(),
                })
            })?);
        }
        let challenges = collect_values::<D, _>(challenges)?;

        // `StepCtx::finish_slots` padded each to the application's capacity.
        D::try_just(move || {
            Ok(FrameworkAux {
                polys: polys.take(),
                claims: claims.take(),
                challenges: challenges.take(),
            })
        })
    }
}

/// The hook-call counts a step body's circuit structure commits to.
///
/// Discovered by the registration-time dry run and replayed at synthesis: a
/// body whose calls diverge from it would synthesize a circuit other than the
/// one that was registered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HookLayout {
    /// What [`derive_challenge`](crate::step::StepCtx::derive_challenge)
    /// requires.
    pub challenge: ChallengeLayout,
    /// What [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query)
    /// requires.
    pub poly_query: PolyQueryLayout,
}

/// What the challenge-derivation hook requires of a step's circuit.
///
/// Kept apart from [`PolyQueryLayout`] because the two are independent
/// framework hooks: challenge derivation provides sound Fiat–Shamir, poly-query
/// provides recursive opening enforcement, and neither implies the other. They
/// share only the registration dry run that discovers them, which is an
/// implementation convenience rather than a relationship between the features.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChallengeLayout {
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge) calls.
    pub calls: usize,
}

/// What the poly-query hook requires of a step's circuit.
///
/// Two counts, not one, and that separation is the point of the mechanism.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolyQueryLayout {
    /// [`witness_polynomial`](crate::step::StepCtx::witness_polynomial) calls —
    /// the expensive count. Each costs a bridge stage with its own commitment,
    /// plus two endoscaling points (one per child) in the next fuse.
    pub polys: usize,
    /// [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) claims —
    /// the cheap count. One instance entry, one quotient in `_08_f`, one triple
    /// in `compute_v`; no commitment, no MSM, no endoscaling point.
    ///
    /// Tracked separately from [`polys`](Self::polys) because a claim names its
    /// polynomial by index, so several claims may share one commitment.
    /// Collapsing them into one number would tax every additional claim at the
    /// polynomial rate, which is the opposite of what this mechanism is for.
    pub claims: usize,
}

impl HookLayout {
    /// The pointwise maximum of two layouts.
    ///
    /// How an application's slot capacity is settled: fold this over every
    /// registered step and the result is the smallest shape that fits them all.
    /// Every count is maximised independently, so an application that opens one
    /// polynomial at many points gets one polynomial slot and many claim slots
    /// rather than the larger of the two in both.
    pub fn max_with(self, other: Self) -> Self {
        Self {
            challenge: ChallengeLayout {
                calls: self.challenge.calls.max(other.challenge.calls),
            },
            poly_query: PolyQueryLayout {
                polys: self.poly_query.polys.max(other.poly_query.polys),
                claims: self.poly_query.claims.max(other.poly_query.claims),
            },
        }
    }
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
}

// Hand-written: `derive` would demand `C: Clone`/`C: Copy`, but the field is a
// field element, `Copy` for every `Cycle`.
impl<C: Cycle> Clone for Alphas<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: Cycle> Copy for Alphas<C> {}

/// The proof-level values a hook needs to compute a witness: the cycle
/// parameters, and the proof's bridge blind source.
///
/// A [`DriverValue`] rather than an `Option`, because its absence is exactly
/// the driver's absence of values — unlike [`HookLayout`], which
/// distinguishes two passes that are *both* structure-only. Every use sits
/// inside a `try_just` that a structure-only driver discards, so no hook body
/// has an absent case to handle. The adapter assembles this once, in its
/// `witness`, from the blinds the driver carried and the parameters it was
/// built with.
pub struct ProofValues<'dr, C: Cycle> {
    pub(crate) params: &'dr C::Params,
    pub(crate) bridge_alpha: C::ScalarField,
}

impl<'dr, C: Cycle> ProofValues<'dr, C> {
    pub(crate) fn new(params: &'dr C::Params, bridge_alpha: C::ScalarField) -> Self {
        Self {
            params,
            bridge_alpha,
        }
    }
}

// Hand-written: `derive` would demand `C: Clone`/`C: Copy`, but the fields are
// a shared reference and a field element, both `Copy` for every `Cycle`.
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
    /// Polynomials witnessed via
    /// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial),
    /// in call order — the in-circuit commitment plus the witness-only
    /// coefficient values.
    pub witnessed_polys: Vec<PolyWires<'dr, D, C::NestedCurve>>,
    /// Opening claims raised via [`FrameworkHooks::enforce_polynomial_query`],
    /// in call order. Each names one of [`witnessed_polys`](Self::witnessed_polys).
    pub poly_queries: Vec<QueryWires<'dr, D>>,
    /// The `(points, challenge)` record per `derive_challenge` call, in slot
    /// order. Its length is the call count the registration-time dry run
    /// discovers.
    pub challenge_pairs: Vec<ChallengeWires<'dr, D, C::NestedCurve>>,
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
    pub fn new(capacity: HookLayout) -> Self {
        Self {
            poly_queries: Vec::new(),
            witnessed_polys: Vec::new(),
            challenge_pairs: Vec::new(),
            expected: None,
            proof_values: <D::MaybeKind as MaybeKind>::empty(),
            capacity,
        }
    }

    /// Creates a hook container for real synthesis: the `derive_challenge` call
    /// count discovered at registration time, and the proof-level values the
    /// hooks commit. Each
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge) call is
    /// checked against the count by `check_layout` once the body has run.
    ///
    /// See [`new`](Self::new) for why this does not delegate to it.
    pub fn with_expected(
        expected: HookLayout,
        capacity: HookLayout,
        proof_values: DriverValue<D, ProofValues<'dr, C>>,
    ) -> Self {
        Self {
            poly_queries: Vec::new(),
            witnessed_polys: Vec::new(),
            challenge_pairs: Vec::new(),
            expected: Some(expected),
            proof_values,
            capacity,
        }
    }

    /// The application's slot capacities; what
    /// [`finish_slots`](crate::step::StepCtx) pads to.
    pub(crate) fn capacity(&self) -> HookLayout {
        self.capacity
    }

    /// The proof-level values the hooks commit to, for the hook bodies that
    /// need them.
    pub(crate) fn proof_values(&self) -> DriverValue<D, ProofValues<'dr, C>> {
        Maybe::clone(&self.proof_values)
    }

    /// The slot the next witnessed polynomial will occupy, in
    /// `witness_polynomial` call order. The call sequence is circuit structure
    /// (discovered by the adapter's dry run), so the assignment is
    /// deterministic.
    ///
    /// Reserving and recording are separate calls because the slot is needed
    /// *before* the commitment exists: it selects the bridge stage, and
    /// therefore the generators, that `com` commits to.
    pub(crate) fn next_poly_slot(&self) -> Result<usize> {
        let slot = self.witnessed_polys.len();
        if slot >= self.capacity.poly_query.polys {
            return Err(Error::InvalidWitness(
                "step witnessed more polynomials than there are polynomial slots".into(),
            ));
        }
        Ok(slot)
    }

    /// Records a witnessed polynomial in the slot
    /// [`next_poly_slot`](Self::next_poly_slot) just returned.
    pub(crate) fn record_polynomial(
        &mut self,
        com: Point<'dr, D, C::NestedCurve>,
        coefficients: DriverValue<D, Vec<D::F>>,
    ) -> Result<()> {
        self.next_poly_slot()?;
        self.witnessed_polys.push(PolyWires { com, coefficients });
        Ok(())
    }

    /// Checks that another challenge slot is available, before the caller does
    /// the work of filling it.
    ///
    /// The challenge twin of [`next_poly_slot`](Self::next_poly_slot):
    /// reserving and recording are separate calls so the failure comes before
    /// the sponge runs, and the count itself lives in one place —
    /// `challenge_pairs`.
    pub(crate) fn reserve_challenge_slot(&self) -> Result<()> {
        if self.challenge_pairs.len() >= self.capacity.challenge.calls {
            return Err(Error::InvalidWitness(
                "step derived more challenges than there are challenge slots".into(),
            ));
        }
        Ok(())
    }

    /// Records a derived challenge's `(points, challenge)` record. The adapter
    /// writes these into the application circuit's public instance, binding
    /// them to its $k(Y)$ so the parent's binding circuit can re-derive the
    /// challenge from the points.
    pub(crate) fn record_challenge(
        &mut self,
        points: Vec<Point<'dr, D, C::NestedCurve>>,
        challenge: Element<'dr, D>,
    ) {
        debug_assert_eq!(points.len(), crate::CHALLENGE_POINTS_PER_CALL);
        self.challenge_pairs
            .push(ChallengeWires { points, challenge });
    }

    /// Records a claim that the polynomial with the given `coefficients`
    /// (little-endian), committed to by `com`, evaluates to `y` at the point
    /// `x`.
    ///
    /// The claim wires occupy one of the application circuit's
    /// claim instance slots,
    /// binding them to the circuit's $k(Y)$; the claim itself is recursively
    /// enforced at the next fuse via the PCS accumulator. The fuse that raises
    /// it additionally pre-checks it natively (see
    /// [`Application::commit_polynomial`](crate::Application::commit_polynomial));
    /// a dishonest witness aborts with [`Error::InvalidWitness`].
    ///
    /// The number of calls per step body is part of the circuit structure: it
    /// must not depend on witness values and must not exceed
    /// the application's claim capacity (checked here).
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
        dr: &mut D,
        poly_slot: usize,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        if self.poly_queries.len() >= self.capacity.poly_query.claims {
            return Err(Error::InvalidWitness(
                "step enforced more poly-queries than there are query slots".into(),
            ));
        }
        if poly_slot >= self.witnessed_polys.len() {
            return Err(Error::InvalidWitness(
                "poly-query names a polynomial slot that was never witnessed".into(),
            ));
        }
        self.poly_queries.push(QueryWires {
            poly_slot: Element::constant(dr, field_index::<D::F>(poly_slot)),
            x,
            y,
        });
        Ok(())
    }

    /// The number of poly-query claim slots filled so far, and the number of
    /// challenge slots. [`StepCtx::finish_slots`](crate::step::StepCtx) reads
    /// these to know how many remain to pad.
    pub(crate) fn claims_filled(&self) -> usize {
        self.poly_queries.len()
    }

    /// See [`claims_filled`](Self::claims_filled).
    pub(crate) fn challenges_filled(&self) -> usize {
        self.challenge_pairs.len()
    }

    /// The number of polynomial slots filled so far.
    pub(crate) fn polys_filled(&self) -> usize {
        self.witnessed_polys.len()
    }

    /// The value of polynomial `slot` at $x = 0$ — its constant term.
    ///
    /// [`StepCtx::finish_slots`](crate::step::StepCtx) uses this to make a
    /// padding query trivially true without special-casing it downstream: the
    /// claim it raises is a real opening of a real polynomial.
    ///
    /// # Panics
    ///
    /// Panics if `slot` has not been witnessed.
    pub(crate) fn poly_at_zero(&self, slot: usize) -> DriverValue<D, D::F> {
        self.witnessed_polys[slot]
            .coefficients
            .as_ref()
            .map(|coefficients| coefficients.first().copied().unwrap_or(D::F::ZERO))
    }

    /// Checks that the step body made exactly the hook calls the registration
    /// dry run discovered, and spends the guard.
    ///
    /// This is the whole determinism rule, in one place and on all three axes:
    /// the synthesized circuit must have the structure that was registered, so
    /// every discovered call must have happened and no more. The `reserve_*`
    /// methods bound the counts against the application's *capacity*, which is
    /// a different question — that a step fits — and they answer it early,
    /// before the work of filling a slot.
    ///
    /// The guard is cleared once checked, because the padding that follows
    /// calls the very same hooks a body does — and it is supposed to exceed the
    /// body's count.
    pub(crate) fn check_layout(&mut self) -> Result<()> {
        let Some(expected) = self.expected.take() else {
            return Ok(());
        };
        for (actual, discovered, hook) in [
            (
                self.challenge_pairs.len(),
                expected.challenge.calls,
                "derive_challenge",
            ),
            (
                self.witnessed_polys.len(),
                expected.poly_query.polys,
                "witness_polynomial",
            ),
            (
                self.poly_queries.len(),
                expected.poly_query.claims,
                "enforce_poly_query",
            ),
        ] {
            if actual != discovered {
                return Err(Error::InvalidWitness(
                    alloc::format!(
                        "{hook} was called {actual} times but registration discovered \
                         {discovered}; circuit structure must not depend on witness values"
                    )
                    .into(),
                ));
            }
        }
        Ok(())
    }

    /// Consumes the container and returns every hook's accumulated output.
    pub fn into_outputs(self) -> FrameworkHookOutputs<'dr, D, C> {
        FrameworkHookOutputs {
            witnessed_polys: self.witnessed_polys,
            poly_queries: self.poly_queries,
            challenge_pairs: self.challenge_pairs,
        }
    }
}

/// Discovery-mode default; see [`FrameworkHooks::new`], including why this does
/// not compile on a value-carrying driver.
impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> Default for FrameworkHooks<'dr, D, C> {
    fn default() -> Self {
        Self::new(HookLayout::default())
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::{
        drivers::emulator::{Emulator, Wireless},
        maybe::Empty,
    };
    use ragu_pasta::{Fp, Pasta};

    use super::*;

    type Dr<'dr> = Emulator<Wireless<Empty, Fp>>;

    /// The framework caps a step body at the application's challenge capacity.
    #[test]
    fn challenge_slots_are_capped() {
        let with_capacity = |calls| {
            FrameworkHooks::<Dr<'_>, Pasta>::new(HookLayout {
                challenge: ChallengeLayout { calls },
                poly_query: PolyQueryLayout::default(),
            })
        };

        with_capacity(1)
            .reserve_challenge_slot()
            .expect("a slot is available");

        let error = with_capacity(0)
            .reserve_challenge_slot()
            .expect_err("a step with no challenge slots cannot derive one");
        assert!(
            alloc::format!("{error}").contains("challenge slots"),
            "unexpected error: {error}"
        );
    }

    /// A body whose hook counts differ from the registration-time dry run is
    /// rejected, rather than silently synthesizing a different circuit. One
    /// check covers all three axes; this pins the shortfall on each.
    #[test]
    fn check_layout_rejects_a_body_that_diverges_from_discovery() {
        for (discovered, hook) in [
            (
                HookLayout {
                    challenge: ChallengeLayout { calls: 1 },
                    poly_query: PolyQueryLayout::default(),
                },
                "derive_challenge",
            ),
            (
                HookLayout {
                    challenge: ChallengeLayout::default(),
                    poly_query: PolyQueryLayout {
                        polys: 1,
                        claims: 0,
                    },
                },
                "witness_polynomial",
            ),
            (
                HookLayout {
                    challenge: ChallengeLayout::default(),
                    poly_query: PolyQueryLayout {
                        polys: 0,
                        claims: 1,
                    },
                },
                "enforce_poly_query",
            ),
        ] {
            // A body that made no calls at all, against a plan expecting one.
            let mut hooks = FrameworkHooks::<Dr<'_>, Pasta>::with_expected(
                discovered,
                discovered,
                <Empty as MaybeKind>::empty::<ProofValues<'_, Pasta>>(),
            );
            let error = hooks
                .check_layout()
                .expect_err("a missing call should be rejected");
            let message = alloc::format!("{error}");
            assert!(message.contains(hook), "unexpected error: {message}");
            assert!(
                message.contains("called 0 times but registration discovered 1"),
                "unexpected error: {message}"
            );
        }
    }

    /// The guard is spent once checked, so the padding that follows — which
    /// calls the same hooks, and is supposed to exceed the body's count — is
    /// not re-judged against the body's plan.
    #[test]
    fn check_layout_is_spent_once() {
        let discovered = HookLayout {
            challenge: ChallengeLayout { calls: 1 },
            poly_query: PolyQueryLayout::default(),
        };
        let mut hooks = FrameworkHooks::<Dr<'_>, Pasta>::with_expected(
            discovered,
            discovered,
            <Empty as MaybeKind>::empty::<ProofValues<'_, Pasta>>(),
        );
        hooks
            .check_layout()
            .expect_err("first check judges the body");
        hooks.check_layout().expect("the guard is spent");
    }

    /// A challenge record's instance region is the same width for every slot:
    /// two wires per input point, plus the challenge. Nothing about it depends
    /// on how many points a call actually passed, which is what lets the
    /// count be witness data rather than circuit structure.
    #[test]
    fn a_challenge_slot_has_one_fixed_instance_width() {
        let per_slot = 2 * crate::CHALLENGE_POINTS_PER_CALL + 1;
        assert_eq!(
            crate::internal::native::stages::preamble::child_num_values(
                0,
                HookLayout {
                    challenge: ChallengeLayout { calls: 1 },
                    poly_query: PolyQueryLayout::default(),
                },
            ) - crate::internal::native::stages::preamble::child_num_values(
                0,
                HookLayout {
                    challenge: ChallengeLayout { calls: 0 },
                    poly_query: PolyQueryLayout::default(),
                },
            ),
            per_slot,
        );
    }
}
