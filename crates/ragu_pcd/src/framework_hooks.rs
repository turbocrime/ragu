//! Framework-side state surfaced to [`Step::witness`](crate::step::Step::witness) impls.
//!
//! [`FrameworkHooks`] bundles the framework's hook-specific state that a step
//! body interacts with through [`StepCtx`](crate::step::StepCtx). It carries
//! three hooks, one per `Vec` of wires it accumulates:
//!
//! * [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial) —
//!   the polynomial slots.
//!   Witnessing a polynomial allocates its bridge commitment as a [`Point`]
//!   plus the two coordinate instance wires (the host commitment's embedded
//!   affine coordinates), and retains the coefficients as a value; the
//!   polynomial itself never enters the circuit. This is the expensive axis —
//!   one bridge stage, one commitment, one MSM and one endoscaling point per
//!   slot — and it is what a claim then names.
//!
//! * [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) —
//!   a polynomial-query claim sink: steps that need to verify a
//!   polynomial-commitment opening — i.e. that the polynomial committed to by
//!   `bridge_com` evaluates to `y` at point `x` — reach it there, and it delegates
//!   here. Each claim carries the opened polynomial's
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
//!   absorbing exactly [`ChallengeLayout::width`] of them.
//!
//! ## Slot counts are declared
//!
//! How many times a step body may call each hook is a property of the
//! application, declared on [`ApplicationBuilder`](crate::ApplicationBuilder)
//! and carried here as [`HookLayout`]. Each hook refuses a call past the
//! capacity, at the call that exceeds it, with [`Error::InvalidWitness`] —
//! see the crate docs for why capacity is declared rather than folded from
//! the registered steps.
//!
//! A call's point count is witness data, not structure: every slot's instance
//! region holds [`ChallengeLayout::width`] points, with the positions a call
//! leaves empty filled by a fixed sentinel.
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
//! challenges.
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
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, Point};

/// A single witnessed polynomial: its bridge commitment and its coefficients.
///
/// The framework needs the coefficients (not just the commitment) so it can
/// check queries at fuse time — and batch the polynomial into the proof
/// system's $(P, u, v)$ accumulator.
pub struct WitnessedPoly<F: Field, C: CurveAffine<Base = F>> {
    /// The polynomial's **bridge** commitment — the nested-curve point the step
    /// witnessed in-circuit, which commits to this claim's bridge stage rather
    /// than to the polynomial. Must equal what the framework derives from the
    /// host commitment of [`coefficients`](Self::coefficients); see
    /// [`Application::commit_polynomial`](crate::Application::commit_polynomial)
    /// and [`PolyHandle`](crate::PolyHandle) for the two-commitment split.
    pub bridge_com: C,
    /// Coefficients of the polynomial $p(X)$, little-endian
    /// (`coefficients[i]` is the coefficient of $X^i$).
    pub coefficients: Vec<F>,
    /// The values of the slot's two coordinate instance wires: the host
    /// commitment's affine coordinates, canonically embedded in the circuit
    /// field.
    pub coords: [F; 2],
}

/// A single opening claim: the polynomial whose bridge commitment is
/// [`bridge_com`](Self::bridge_com) evaluates to `y` at `x`.
///
/// Several of these may carry the same `bridge_com` — that is what makes a
/// repeat opening cheap.
pub struct PolyQueryClaim<C: CurveAffine, F: Field> {
    /// The opened polynomial's bridge commitment — the same value the step's
    /// [`WitnessedPoly::bridge_com`] records for it.
    pub bridge_com: C,
    /// Point at which the polynomial is opened.
    pub x: F,
    /// Claimed evaluation $p(x) = y$.
    pub y: F,
}

/// The in-circuit wires of a derived challenge: the points it was hashed from,
/// and the challenge itself. All of them go into the application circuit's
/// public instance so the parent can re-derive the challenge from the points.
pub struct ChallengeWires<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// The slot's input points, exactly [`ChallengeLayout::width`] of them:
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
/// call. `bridge_com` is the polynomial's identity *within this proof*, and a
/// claim that opens it carries **this same [`Point`]** — `enforce_polynomial_query`
/// reads it from here, so the polynomial region and the claim region hold one
/// wire at two instance positions and their equality needs no constraint.
pub struct PolyWires<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// The bridge commitment point, as witnessed by the step.
    pub bridge_com: Point<'dr, D, C>,
    /// The polynomial's coefficient values (witness-only; never wires).
    pub coefficients: DriverValue<D, Vec<D::F>>,
    /// The slot's two coordinate instance wires: the host commitment's affine
    /// coordinates, canonically embedded, allocated at witnessing as plain
    /// value-filled wires — free wires, and still fail-closed: the
    /// accumulator forces them to be the recorded host's embedded
    /// coordinates, or no proof exists.
    pub coords: [Element<'dr, D>; 2],
    /// Whether [`poly_limbs`](crate::step::StepCtx::poly_limbs) has tied its
    /// bit-derived coordinates to the wires; a second tie is refused.
    pub tied: bool,
}

/// The in-circuit wires of a single **query**: which polynomial is opened,
/// where, and to what.
///
/// One of these per [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query)
/// call. Several queries may carry the same `bridge_com` — that is the point of
/// the split, and it is why a repeat opening costs only these four elements.
pub struct QueryWires<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// The opened polynomial's bridge commitment — **the same [`Point`] the
    /// polynomial's own slot holds**, one wire written at two instance
    /// positions.
    pub bridge_com: Point<'dr, D, C>,
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
/// constructs this, passes it to the step, then drains it into
/// [`FrameworkHookOutputs`] and surfaces that through its `Aux` for later
/// fuse-time processing.
///
/// Constructing and draining one is the adapter's business, so both are
/// crate-internal; a step reaches the hooks through
/// [`StepCtx`](crate::step::StepCtx).
pub struct FrameworkHooks<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    /// One entry per [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query)
    /// call, in call order.
    poly_queries: Vec<QueryWires<'dr, D, C::NestedCurve>>,
    /// One entry per
    /// [`witness_polynomial`](crate::step::StepCtx::witness_polynomial) call,
    /// in call order. A polynomial's position here is its slot, which fixes the
    /// bridge stage — and therefore the generator positions — its `bridge_com` commits
    /// to, and is what a query names.
    witnessed_polys: Vec<PolyWires<'dr, D, C::NestedCurve>>,
    /// The `(points, challenge)` record each
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge) call
    /// produced, in slot order. Its length *is* the call count.
    challenge_pairs: Vec<ChallengeWires<'dr, D, C::NestedCurve>>,
    /// The proof-level values the hooks commit to. See [`ProofValues`].
    proof_values: DriverValue<D, ProofValues<'dr, C>>,
    /// The application's declared slot capacities: what every circuit's
    /// instance exposes, what padding fills to, and what each hook checks
    /// calls against.
    capacity: HookLayout,
}

/// Every hook's output as plain values, for the fuse.
///
/// The value-level counterpart of [`FrameworkHookOutputs`], which holds
/// in-circuit wires. A step circuit's `Aux` carries one of these beside the
/// step's own `Aux`; adding a hook means adding a field here, which the
/// compiler forces every drain site to acknowledge.
pub struct FrameworkAux<C: Cycle> {
    /// The step's witnessed polynomials, padded to the application's poly
    /// capacity, in slot order — matching the instance layout the circuit
    /// committed to. Each carries its coefficients, which the fuse folds into
    /// the PCS accumulator.
    pub polys: Vec<WitnessedPoly<C::CircuitField, C::NestedCurve>>,
    /// The step's opening claims, padded to the application's claim capacity,
    /// in call order. Each carries the commitment of one of
    /// [`polys`](Self::polys). Fuse pre-checks every claim natively, persists
    /// the claim instances in the proof, and the *next* fuse enforces them
    /// recursively via the PCS accumulator.
    pub claims: Vec<PolyQueryClaim<C::NestedCurve, C::CircuitField>>,
    /// The derived-challenge records the circuit exposes, padded to the
    /// application's challenge capacity, in slot order.
    pub challenges: Vec<crate::proof::ChallengeOpening<C::NestedCurve, C::CircuitField>>,
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

/// The slot capacities an application declares, as the value that travels
/// downstream of the [`ApplicationBuilder`](crate::ApplicationBuilder) consts.
///
/// Every application circuit exposes exactly these counts, whatever its own step
/// used, so a step's circuit shape is settled the moment it registers rather
/// than at the last registration. A body that calls a hook past its capacity is
/// refused at the call that exceeds it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HookLayout {
    /// What [`derive_challenge`](crate::step::StepCtx::derive_challenge)
    /// requires.
    pub challenge: ChallengeLayout,
    /// What [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query)
    /// requires.
    pub poly_query: PolyQueryLayout,
}

impl HookLayout {
    /// The capacity an application's declared parameters state — the one place
    /// the four consts on [`ApplicationBuilder`](crate::ApplicationBuilder)
    /// turn into the value every circuit is built from. `const` so its callers
    /// can be associated constants.
    pub const fn declared(polys: usize, claims: usize, calls: usize, width: usize) -> Self {
        Self {
            challenge: ChallengeLayout { calls, width },
            poly_query: PolyQueryLayout { polys, claims },
        }
    }
}

/// What the challenge-derivation hook requires of a step's circuit.
///
/// Kept apart from [`PolyQueryLayout`]: the two hooks are independent
/// features, sharing only the [`HookLayout`] that carries them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChallengeLayout {
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge) calls.
    pub calls: usize,
    /// The challenge width: how many input points one call absorbs. Every
    /// call's instance region holds exactly this many, with the positions a
    /// caller leaves empty taking a fixed sentinel. Its cost is
    /// [`permutations`](ChallengeLayout::permutations).
    pub width: usize,
}

impl ChallengeLayout {
    /// The absorb permutations one call of this width costs, at `rate`:
    /// `⌈2w / rate⌉` (a point is two coordinates). Paid by
    /// `challenge_binding` once per `(child, slot)`, out of the framework's
    /// gate budget.
    pub const fn permutations(width: usize, rate: usize) -> usize {
        (2 * width).div_ceil(rate)
    }
}

/// What the poly-query hook requires of a step's circuit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PolyQueryLayout {
    /// [`witness_polynomial`](crate::step::StepCtx::witness_polynomial) calls —
    /// the expensive count. Each costs a bridge stage with its own commitment,
    /// plus two endoscaling points (one per child) in the next fuse.
    pub polys: usize,
    /// [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) claims —
    /// the cheap count: four instance elements, one quotient in `_08_f`, one
    /// term in `compute_v`. A separate flat pool, so several claims can open
    /// one polynomial at the claim rate.
    pub claims: usize,
}

/// The proof-level values a hook needs to compute a witness: the cycle
/// parameters, and the proof's bridge blind source.
///
/// A [`DriverValue`] because its absence is exactly the driver's absence of
/// values: every use sits inside a `try_just` that a structure-only driver
/// discards. The adapter assembles this once, in its `witness`.
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

// Hand-written to avoid `derive`'s `C: Clone`/`C: Copy` bounds; the fields are
// a shared reference and a field element, both `Copy` for every `Cycle`.
impl<C: Cycle> Clone for ProofValues<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: Cycle> Copy for ProofValues<'_, C> {}

/// Aggregate of every hook's accumulated output, drained from a
/// [`FrameworkHooks`] once the step body has run. Adding a new hook means adding
/// a field here, which forces every drain site to acknowledge it.
pub struct FrameworkHookOutputs<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    /// Polynomials witnessed via
    /// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial),
    /// in call order — the in-circuit commitment plus the witness-only
    /// coefficient values.
    pub witnessed_polys: Vec<PolyWires<'dr, D, C::NestedCurve>>,
    /// Opening claims raised via
    /// [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query),
    /// in call order. Each carries the `bridge_com` of one of
    /// [`witnessed_polys`](Self::witnessed_polys) — the same wire, not a copy.
    pub poly_queries: Vec<QueryWires<'dr, D, C::NestedCurve>>,
    /// The `(points, challenge)` record per `derive_challenge` call, in slot
    /// order. Padded to the application's declared challenge capacity by
    /// [`StepCtx::finish_slots`](crate::step::StepCtx), so its length is that
    /// capacity rather than what the body used.
    pub challenge_pairs: Vec<ChallengeWires<'dr, D, C::NestedCurve>>,
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> FrameworkHookOutputs<'dr, D, C> {
    /// Reads each hook's wires back out as plain values, for the fuse.
    pub(crate) fn into_values(self) -> Result<DriverValue<D, FrameworkAux<C>>> {
        let mut polys = Vec::with_capacity(self.witnessed_polys.len());
        for PolyWires {
            bridge_com,
            coefficients,
            coords,
            tied: _,
        } in self.witnessed_polys
        {
            polys.push(D::try_just(|| {
                Ok(WitnessedPoly {
                    bridge_com: bridge_com.value().take(),
                    coefficients: coefficients.take(),
                    coords: [*coords[0].value().take(), *coords[1].value().take()],
                })
            })?);
        }
        let polys = collect_values::<D, _>(polys)?;

        let mut claims = Vec::with_capacity(self.poly_queries.len());
        for QueryWires { bridge_com, x, y } in self.poly_queries {
            claims.push(D::try_just(|| {
                Ok(PolyQueryClaim {
                    bridge_com: bridge_com.value().take(),
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

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> FrameworkHooks<'dr, D, C> {
    /// Creates a hook container at the application's declared `capacity`, with
    /// the proof-level values the hooks commit to.
    ///
    /// There is one constructor because there is one pass. The capacity is
    /// declared, so nothing has to be learned from the step body first — each
    /// hook simply refuses a call past the capacity, at the call that exceeds
    /// it.
    pub(crate) fn new(
        capacity: HookLayout,
        proof_values: DriverValue<D, ProofValues<'dr, C>>,
    ) -> Self {
        Self {
            poly_queries: Vec::new(),
            witnessed_polys: Vec::new(),
            challenge_pairs: Vec::new(),
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
    /// `witness_polynomial` call order. The call sequence is circuit structure —
    /// it must not depend on witness values — so the assignment is
    /// deterministic.
    ///
    /// Reserving and recording are separate calls because the slot is needed
    /// *before* the commitment exists: it selects the bridge stage, and
    /// therefore the generators, that `bridge_com` commits to.
    pub(crate) fn next_poly_slot(&self) -> Result<usize> {
        let slot = self.witnessed_polys.len();
        if slot >= self.capacity.poly_query.polys {
            return Err(Error::InvalidWitness(
                "step witnessed more polynomials than there are polynomial slots".into(),
            ));
        }
        Ok(slot)
    }

    /// Records a witnessed polynomial in `slot`, which
    /// [`next_poly_slot`](Self::next_poly_slot) returned to the caller — the
    /// caller already holds it to pick the bridge stage before the commitment
    /// exists. The debug assertion pins that the two agree.
    pub(crate) fn record_polynomial(
        &mut self,
        slot: usize,
        bridge_com: Point<'dr, D, C::NestedCurve>,
        coefficients: DriverValue<D, Vec<D::F>>,
        coords: [Element<'dr, D>; 2],
    ) {
        debug_assert_eq!(
            slot,
            self.witnessed_polys.len(),
            "a polynomial must be recorded in the slot next_poly_slot returned"
        );
        self.witnessed_polys.push(PolyWires {
            bridge_com,
            coefficients,
            coords,
            tied: false,
        });
    }

    /// Ties the coordinates [`poly_limbs`](crate::step::StepCtx::poly_limbs)
    /// derived from the step's own constrained bits to `slot`'s coordinate
    /// instance wires.
    ///
    /// # Errors
    ///
    /// Rejects a second call for the same slot: the first call's bits are
    /// already tied.
    pub(crate) fn tie_coords(
        &mut self,
        dr: &mut D,
        slot: usize,
        derived: [Element<'dr, D>; 2],
    ) -> Result<()> {
        let wires = self.witnessed_polys.get_mut(slot).ok_or_else(|| {
            Error::InvalidWitness("poly_limbs called for a slot that was never witnessed".into())
        })?;
        if wires.tied {
            return Err(Error::InvalidWitness(
                "poly_limbs may only be called once per handle".into(),
            ));
        }
        wires.tied = true;
        for (derived, wire) in derived.into_iter().zip(wires.coords.clone()) {
            derived.enforce_equal(dr, &wire)?;
        }
        Ok(())
    }

    /// Checks that another challenge slot is available, before the caller does
    /// the work of filling it — the challenge twin of
    /// [`next_poly_slot`](Self::next_poly_slot).
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
        debug_assert_eq!(points.len(), self.capacity.challenge.width);
        self.challenge_pairs
            .push(ChallengeWires { points, challenge });
    }

    /// Records a claim that the polynomial with the given `coefficients`
    /// (little-endian), committed to by `bridge_com`, evaluates to `y` at the point
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
    /// `bridge_com` is the [`Point`] the caller's
    /// [`PolyHandle`](crate::PolyHandle) holds — the same wire the polynomial
    /// region writes — and a `PolyHandle` can only come from
    /// [`witness_polynomial`](crate::step::StepCtx::witness_polynomial), so a
    /// claim names a witnessed polynomial by construction. Claims may be
    /// raised in any order and several may open one polynomial; a repeat
    /// opening costs a claim slot and no polynomial slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`] if the step has already filled every
    /// claim slot the application declared.
    pub(crate) fn enforce_polynomial_query(
        &mut self,
        bridge_com: Point<'dr, D, C::NestedCurve>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        if self.poly_queries.len() >= self.capacity.poly_query.claims {
            return Err(Error::InvalidWitness(
                "step enforced more poly-queries than there are query slots".into(),
            ));
        }
        self.poly_queries.push(QueryWires { bridge_com, x, y });
        Ok(())
    }

    /// Fills one unused claim slot with the canonical padding query.
    ///
    /// Separate from [`enforce_polynomial_query`](Self::enforce_polynomial_query)
    /// because padding has no [`PolyHandle`](crate::PolyHandle) to name — it
    /// runs after the step body, against slot 0, whose `bridge_com` this
    /// container already holds; the step-facing path stays free of slot
    /// indices.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`] if no claim slot is free, or if no
    /// polynomial slot was ever filled — a claim has to name a polynomial.
    pub(crate) fn enforce_padding_query(
        &mut self,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        let bridge_com = self
            .witnessed_polys
            .first()
            .ok_or_else(|| {
                Error::InvalidWitness("a padding claim requires a polynomial slot to name".into())
            })?
            .bridge_com
            .clone();
        self.enforce_polynomial_query(bridge_com, x, y)
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

    /// The value of the first witnessed polynomial at $x = 0$ — its constant
    /// term. [`StepCtx::finish_slots`](crate::step::StepCtx) pairs this with
    /// the `bridge_com` [`enforce_padding_query`](Self::enforce_padding_query)
    /// reads from the same slot, so a padding query is a real, trivially true
    /// opening.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`] if no polynomial was ever witnessed.
    pub(crate) fn first_poly_at_zero(&self) -> Result<DriverValue<D, D::F>> {
        Ok(self
            .witnessed_polys
            .first()
            .ok_or_else(|| {
                Error::InvalidWitness("a padding claim requires a polynomial slot to name".into())
            })?
            .coefficients
            .as_ref()
            .map(|coefficients| coefficients.first().copied().unwrap_or(D::F::ZERO)))
    }

    /// Consumes the container and returns every hook's accumulated output.
    pub(crate) fn into_outputs(self) -> FrameworkHookOutputs<'dr, D, C> {
        FrameworkHookOutputs {
            witnessed_polys: self.witnessed_polys,
            poly_queries: self.poly_queries,
            challenge_pairs: self.challenge_pairs,
        }
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::{
        drivers::emulator::{Emulator, Wireless},
        maybe::{Empty, MaybeKind},
    };
    use ragu_pasta::{Fp, Pasta};

    use super::*;

    type Dr<'dr> = Emulator<Wireless<Empty, Fp>>;

    /// The framework caps a step body at the application's challenge capacity.
    #[test]
    fn challenge_slots_are_capped() {
        let with_capacity = |calls| {
            FrameworkHooks::<Dr<'_>, Pasta>::new(
                HookLayout {
                    challenge: ChallengeLayout { calls, width: 2 },
                    poly_query: PolyQueryLayout::default(),
                },
                <Empty as MaybeKind>::empty::<ProofValues<'_, Pasta>>(),
            )
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

    /// A challenge record's instance region is the same width for every slot:
    /// two wires per input point, plus the challenge. Nothing about it depends
    /// on how many points a call actually passed, which is what lets the
    /// count be witness data rather than circuit structure.
    ///
    /// Measured against the stage that holds the region — the challenge slots
    /// are their own stage, not part of the preamble.
    #[test]
    fn a_challenge_slot_has_one_fixed_instance_width() {
        use crate::internal::native::stages::slots::num_values;

        let width = 2;
        // `num_values` covers both children, so one call's worth is half the
        // step from zero calls to one.
        assert_eq!(
            (num_values(1, width) - num_values(0, width)) / 2,
            2 * width + 1,
        );
        // And it stays that width however many calls there are.
        assert_eq!(
            (num_values(4, width) - num_values(3, width)) / 2,
            2 * width + 1,
        );
    }

    /// The declared width's cost: a point is two coordinates and a permutation
    /// absorbs `RATE` of them, so `w` points cost `⌈2w / RATE⌉` permutations.
    /// A partly-filled permutation still costs a whole one.
    #[test]
    fn permutations_follow_the_width() {
        assert_eq!(ChallengeLayout::permutations(0, 4), 0);
        assert_eq!(ChallengeLayout::permutations(1, 4), 1);
        assert_eq!(ChallengeLayout::permutations(2, 4), 1);
        assert_eq!(ChallengeLayout::permutations(3, 4), 2);
        assert_eq!(ChallengeLayout::permutations(4, 4), 2);
        // An odd rate still rounds up.
        assert_eq!(ChallengeLayout::permutations(2, 3), 2);
    }
}
