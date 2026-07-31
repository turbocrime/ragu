//! Framework-side state surfaced to [`Step::witness`](crate::step::Step::witness) impls.
//!
//! [`FrameworkHooks`] bundles the framework's hook-specific state that a step
//! body interacts with through [`StepCtx`](crate::step::StepCtx). It carries
//! three hooks, one per `Vec` of wires it accumulates:
//!
//! * [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial) —
//!   the polynomial slots.
//!   Witnessing a polynomial allocates its two coordinate instance wires (the
//!   host commitment's embedded affine coordinates — its name), and retains
//!   the coefficients as a value; the polynomial itself never enters the
//!   circuit. This is the expensive axis — one MSM and one endoscaling point
//!   per slot — and it is what a claim then names.
//!
//! * [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) —
//!   a polynomial-query claim sink: steps that need to verify a
//!   polynomial-commitment opening — i.e. that the polynomial the claim names
//!   evaluates to `y` at point `x` — reach it there, and it delegates
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
//!   the slot cap, the determinism guard, and the `(inputs, challenge)` records
//!   the adapter writes into the application circuit's public instance. Every
//!   application circuit gets the application's challenge capacity in slots, each
//!   absorbing exactly [`ChallengeLayout::width`] elements.
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
//! A call's input count is witness data, not structure: every slot's instance
//! region holds [`ChallengeLayout::width`] elements, with the positions a call
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

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{Element, vec::Len};

/// A single witnessed polynomial: its embedded commitment coordinates and its
/// coefficients.
///
/// The framework needs the coefficients (not just the commitment) so it can
/// check queries at fuse time — and batch the polynomial into the proof
/// system's $(P, u, v)$ accumulator.
pub struct WitnessedPoly<F: Field> {
    /// Coefficients of the polynomial $p(X)$, little-endian
    /// (`coefficients[i]` is the coefficient of $X^i$).
    pub coefficients: Vec<F>,
    /// The values of the slot's two coordinate instance wires: the host
    /// commitment's affine coordinates, canonically embedded in the circuit
    /// field. The polynomial's in-circuit identity.
    pub coords: [F; 2],
}

/// A single opening claim: the polynomial whose embedded commitment
/// coordinates are [`coords`](Self::coords) evaluates to `y` at `x`.
///
/// Several of these may carry the same `coords` — that is what makes a repeat
/// opening cheap.
pub struct PolyQueryClaim<F: Field> {
    /// The opened polynomial's embedded commitment coordinates — the same
    /// values the step's [`WitnessedPoly::coords`] records for it.
    pub coords: [F; 2],
    /// Point at which the polynomial is opened.
    pub x: F,
    /// Claimed evaluation $p(x) = y$.
    pub y: F,
}

/// The in-circuit wires of a derived challenge: the field elements it was
/// hashed from, and the challenge itself. All of them go into the application
/// circuit's public instance so the parent can re-derive the challenge from
/// the inputs.
pub struct ChallengeWires<'dr, D: Driver<'dr>> {
    /// The slot's input elements, exactly [`ChallengeLayout::width`] of them:
    /// the caller's, then the sentinel in each position left empty.
    pub inputs: Vec<Element<'dr, D>>,
    /// The challenge, hashed from [`inputs`](Self::inputs).
    pub challenge: Element<'dr, D>,
}

/// The in-circuit wires of a single witnessed **polynomial**, retained so the
/// adapter can write them into the application circuit's public instance
/// (binding them to the circuit's $k(Y)$), alongside the witness-only
/// coefficient values the fuse needs for the PCS folding.
///
/// One of these per [`witness_polynomial`](crate::step::StepCtx::witness_polynomial)
/// call. `coords` is the polynomial's identity, and a claim that opens it
/// carries **these same wires** — `enforce_polynomial_query` reads them from
/// here, so the polynomial region and the claim region hold one pair of wires
/// at two instance positions and their equality needs no constraint.
pub struct PolyWires<'dr, D: Driver<'dr>> {
    /// The polynomial's coefficient values (witness-only; never wires).
    pub coefficients: DriverValue<D, Vec<D::F>>,
    /// The slot's two coordinate instance wires: the commitment's
    /// representation, allocated at witnessing as plain value-filled wires —
    /// free wires, and still fail-closed: the accumulator and the root
    /// recompute force them to be the recorded host's, or no proof exists.
    pub coords: [Element<'dr, D>; 2],
}

/// The in-circuit wires of a single **query**: which polynomial is opened,
/// where, and to what.
///
/// One of these per [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query)
/// call. Several queries may carry the same `coords` — that is the point of
/// the split, and it is why a repeat opening costs only these four elements.
pub struct QueryWires<'dr, D: Driver<'dr>> {
    /// The opened polynomial's embedded commitment coordinates — **the same
    /// wires the polynomial's own slot holds**, one pair written at two
    /// instance positions.
    pub coords: [Element<'dr, D>; 2],
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
    poly_queries: Vec<QueryWires<'dr, D>>,
    /// One entry per
    /// [`witness_polynomial`](crate::step::StepCtx::witness_polynomial) call,
    /// in call order. A polynomial's position here is its slot.
    witnessed_polys: Vec<PolyWires<'dr, D>>,
    /// The `(inputs, challenge)` record each
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge) call
    /// produced, in slot order. Its length *is* the call count.
    challenge_pairs: Vec<ChallengeWires<'dr, D>>,
    /// The cycle parameters, for the hook bodies that compute witness values.
    /// A [`DriverValue`] because their absence is exactly the driver's
    /// absence of values: every use sits inside a `try_just` that a
    /// structure-only driver discards.
    params: DriverValue<D, &'dr C::Params>,
    /// The application's declared slot capacities: what every circuit's
    /// instance exposes, what padding fills to, and what each hook checks
    /// calls against.
    hook_layout: HookLayout,
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
    pub polys: Vec<WitnessedPoly<C::CircuitField>>,
    /// The step's opening claims, padded to the application's claim capacity,
    /// in call order. Each carries the embedded commitment coordinates of one
    /// of [`polys`](Self::polys). Fuse pre-checks every claim natively,
    /// persists the claim instances in the proof, and the *next* fuse
    /// enforces them recursively via the PCS accumulator.
    pub claims: Vec<PolyQueryClaim<C::CircuitField>>,
    /// The derived-challenge records the circuit exposes, padded to the
    /// application's challenge capacity, in slot order.
    pub challenges: Vec<crate::proof::ChallengeOpening<C::CircuitField>>,
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

/// The hook capacities of an application, as type-level lengths on a marker
/// type. Usually written as [`AppHooks`] rather than implemented by hand.
///
/// Each member is a [`Len`], so it slots directly into the `FixedVec`s the
/// framework sizes with it; the plain numbers are read back through the
/// provided accessors ([`polys`](Self::polys), [`claims`](Self::claims),
/// [`challenges`](Self::challenges),
/// [`challenge_width`](Self::challenge_width)).
///
/// [`PolyCount`](Self::PolyCount) is how many
/// [`witness_polynomial`](crate::step::StepCtx::witness_polynomial) slots
/// any one step may fill — the expensive axis: a bridge stage, a
/// commitment, an MSM, and an endoscaling point per child, each.
/// [`ClaimCount`](Self::ClaimCount) is how many
/// [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) claims
/// it may raise — the cheap axis: one instance triple, one `_08_f`
/// quotient, one `compute_v` triple. A repeat opening costs a claim slot
/// and no polynomial slot.
///
/// [`ChallengeCount`](Self::ChallengeCount) is how many
/// [`derive_challenge`](crate::step::StepCtx::derive_challenge) calls any
/// one step may make, and [`ChallengeWidth`](Self::ChallengeWidth) the
/// widest input one call may pass, in field elements — a
/// [`coords`](crate::PolyHandle::coords) pair is two; the width's cost is
/// [`ChallengeLayout::permutations`](crate::framework_hooks::ChallengeLayout::permutations),
/// paid by the internal `challenge_binding` circuit per `(child, slot)`.
///
/// Every step of an application exposes exactly these counts, whatever it
/// uses; unused slots are padded by the framework, and a step that asks for
/// more than the declared capacity is refused at the call that exceeds it.
pub trait HookConfig: Send + Sync + 'static {
    /// Polynomial witnesses committed per step.
    type PolyWitnesses: Len;
    /// Polynomial queries enforced per step.
    type PolyQueries: Len;
    /// Challenges derived per step.
    type ChallengeDerivations: Len;
    /// Input elements one challenge derivation may absorb.
    type ChallengeWidth: Len;

    /// The declared capacities as the value every circuit is built from —
    /// the [`framework_hooks`](crate::framework_hooks) form of this layout.
    fn hook_layout() -> HookLayout {
        HookLayout {
            challenge: Self::challenge_layout(),
            poly_query: Self::poly_query_layout(),
        }
    }

    /// The challenge layout for this application.
    fn challenge_layout() -> ChallengeLayout {
        ChallengeLayout {
            calls: Self::ChallengeDerivations::len(),
            width: Self::ChallengeWidth::len(),
        }
    }

    /// The poly-query layout for this application.
    fn poly_query_layout() -> PolyQueryLayout {
        PolyQueryLayout {
            polys: Self::PolyWitnesses::len(),
            claims: Self::PolyQueries::len(),
        }
    }
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
    /// The challenge width: how many input field elements one call absorbs.
    /// Every call's instance region holds exactly this many, with the
    /// positions a caller leaves empty taking a fixed sentinel. A
    /// [`PolyHandle::coords`](crate::poly_commitment::PolyHandle::coords)
    /// pair is two; a pinned point's coordinates are two. Its cost is
    /// [`permutations`](ChallengeLayout::permutations).
    pub width: usize,
}

impl ChallengeLayout {
    /// The absorb permutations one call of this width costs, at `rate`:
    /// `⌈w / rate⌉`. Paid by `challenge_binding` once per `(child, slot)`,
    /// out of the framework's gate budget.
    pub const fn permutations(width: usize, rate: usize) -> usize {
        width.div_ceil(rate)
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

/// Aggregate of every hook's accumulated output, drained from a
/// [`FrameworkHooks`] once the step body has run. Adding a new hook means adding
/// a field here, which forces every drain site to acknowledge it.
pub struct FrameworkHookOutputs<'dr, D: Driver<'dr>> {
    /// Polynomials witnessed via
    /// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial),
    /// in call order — the in-circuit commitment coordinates plus the
    /// witness-only coefficient values.
    pub witnessed_polys: Vec<PolyWires<'dr, D>>,
    /// Opening claims raised via
    /// [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query),
    /// in call order. Each carries the `coords` of one of
    /// [`witnessed_polys`](Self::witnessed_polys) — the same wires, not
    /// copies.
    pub poly_queries: Vec<QueryWires<'dr, D>>,
    /// The `(points, challenge)` record per `derive_challenge` call, in slot
    /// order. Padded to the application's declared challenge capacity by
    /// [`StepCtx::finish_slots`](crate::step::StepCtx), so its length is that
    /// capacity rather than what the body used.
    pub challenge_pairs: Vec<ChallengeWires<'dr, D>>,
}

impl<'dr, D: Driver<'dr>> FrameworkHookOutputs<'dr, D> {
    /// Reads each hook's wires back out as plain values, for the fuse.
    pub(crate) fn into_values<C: Cycle<CircuitField = D::F>>(
        self,
    ) -> Result<DriverValue<D, FrameworkAux<C>>> {
        let mut polys = Vec::with_capacity(self.witnessed_polys.len());
        for PolyWires {
            coefficients,
            coords,
        } in self.witnessed_polys
        {
            polys.push(D::try_just(|| {
                Ok(WitnessedPoly {
                    coefficients: coefficients.take(),
                    coords: [*coords[0].value().take(), *coords[1].value().take()],
                })
            })?);
        }
        let polys = collect_values::<D, _>(polys)?;

        let mut claims = Vec::with_capacity(self.poly_queries.len());
        for QueryWires { coords, x, y } in self.poly_queries {
            claims.push(D::try_just(|| {
                Ok(PolyQueryClaim {
                    coords: [*coords[0].value().take(), *coords[1].value().take()],
                    x: *x.value().take(),
                    y: *y.value().take(),
                })
            })?);
        }
        let claims = collect_values::<D, _>(claims)?;

        let mut challenges = Vec::with_capacity(self.challenge_pairs.len());
        for pair in self.challenge_pairs {
            challenges.push(D::try_just(|| {
                let mut inputs = Vec::with_capacity(pair.inputs.len());
                for input in &pair.inputs {
                    inputs.push(*input.value().take());
                }
                Ok(crate::proof::ChallengeOpening {
                    inputs,
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
    pub(crate) fn new(hook_layout: HookLayout, params: DriverValue<D, &'dr C::Params>) -> Self {
        Self {
            poly_queries: Vec::new(),
            witnessed_polys: Vec::new(),
            challenge_pairs: Vec::new(),
            params,
            hook_layout,
        }
    }

    /// The application's slot capacities; what
    /// [`finish_slots`](crate::step::StepCtx) pads to.
    pub(crate) fn hook_layout(&self) -> HookLayout {
        self.hook_layout
    }

    /// The cycle parameters, for the hook bodies that compute witness values.
    pub(crate) fn params(&self) -> DriverValue<D, &'dr C::Params> {
        Maybe::clone(&self.params)
    }

    /// The slot the next witnessed polynomial will occupy, in
    /// `witness_polynomial` call order. The call sequence is circuit structure —
    /// it must not depend on witness values — so the assignment is
    /// deterministic.
    pub(crate) fn next_poly_slot(&self) -> Result<usize> {
        let slot = self.witnessed_polys.len();
        if slot >= self.hook_layout.poly_query.polys {
            return Err(Error::InvalidWitness(
                "step witnessed more polynomials than there are polynomial slots".into(),
            ));
        }
        Ok(slot)
    }

    /// Records a witnessed polynomial in `slot`, which
    /// [`next_poly_slot`](Self::next_poly_slot) returned to the caller. The
    /// debug assertion pins that the two agree.
    pub(crate) fn record_polynomial(
        &mut self,
        slot: usize,
        coefficients: DriverValue<D, Vec<D::F>>,
        coords: [Element<'dr, D>; 2],
    ) {
        debug_assert_eq!(
            slot,
            self.witnessed_polys.len(),
            "a polynomial must be recorded in the slot next_poly_slot returned"
        );
        self.witnessed_polys.push(PolyWires {
            coefficients,
            coords,
        });
    }

    /// Checks that another challenge slot is available, before the caller does
    /// the work of filling it — the challenge twin of
    /// [`next_poly_slot`](Self::next_poly_slot).
    pub(crate) fn reserve_challenge_slot(&self) -> Result<()> {
        if self.challenge_pairs.len() >= self.hook_layout.challenge.calls {
            return Err(Error::InvalidWitness(
                "step derived more challenges than there are challenge slots".into(),
            ));
        }
        Ok(())
    }

    /// Records a derived challenge's `(inputs, challenge)` record. The adapter
    /// writes these into the application circuit's public instance, binding
    /// them to its $k(Y)$ so the parent's binding circuit can re-derive the
    /// challenge from the inputs.
    pub(crate) fn record_challenge(
        &mut self,
        inputs: Vec<Element<'dr, D>>,
        challenge: Element<'dr, D>,
    ) {
        debug_assert_eq!(inputs.len(), self.hook_layout.challenge.width);
        self.challenge_pairs
            .push(ChallengeWires { inputs, challenge });
    }

    /// Records a claim that the polynomial named by `coords` evaluates to `y`
    /// at the point `x`.
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
    /// `coords` are the wires the caller's
    /// [`PolyHandle`](crate::PolyHandle) holds — the same wires the
    /// polynomial region writes — and a `PolyHandle` can only come from
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
        coords: [Element<'dr, D>; 2],
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        if self.poly_queries.len() >= self.hook_layout.poly_query.claims {
            return Err(Error::InvalidWitness(
                "step enforced more poly-queries than there are query slots".into(),
            ));
        }
        self.poly_queries.push(QueryWires { coords, x, y });
        Ok(())
    }

    /// Fills one unused claim slot with the canonical padding query.
    ///
    /// Separate from [`enforce_polynomial_query`](Self::enforce_polynomial_query)
    /// because padding has no [`PolyHandle`](crate::PolyHandle) to name — it
    /// runs after the step body, against slot 0, whose `coords` this
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
        let coords = self
            .witnessed_polys
            .first()
            .ok_or_else(|| {
                Error::InvalidWitness("a padding claim requires a polynomial slot to name".into())
            })?
            .coords
            .clone();
        self.enforce_polynomial_query(coords, x, y)
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
    /// the `coords` [`enforce_padding_query`](Self::enforce_padding_query)
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
    pub(crate) fn into_outputs(self) -> FrameworkHookOutputs<'dr, D> {
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
                <Empty as MaybeKind>::empty::<&<Pasta as Cycle>::Params>(),
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
    /// one wire per input element, plus the challenge. Nothing about it
    /// depends on how many elements a call actually passed, which is what
    /// lets the count be witness data rather than circuit structure.
    ///
    /// Measured against the stage that holds the region — the challenge slots
    /// are their own stage, not part of the preamble.
    #[test]
    fn a_challenge_slot_has_one_fixed_instance_width() {
        use crate::internal::native::stages::slots::num_values;

        let width = 2;
        // `num_values` covers both children, so one call's worth is half the
        // step from zero calls to one.
        assert_eq!((num_values(1, width) - num_values(0, width)) / 2, width + 1,);
        // And it stays that width however many calls there are.
        assert_eq!((num_values(4, width) - num_values(3, width)) / 2, width + 1,);
    }

    /// The declared width's cost: a permutation absorbs `RATE` elements, so
    /// `w` elements cost `⌈w / RATE⌉` permutations. A partly-filled
    /// permutation still costs a whole one.
    #[test]
    fn permutations_follow_the_width() {
        assert_eq!(ChallengeLayout::permutations(0, 4), 0);
        assert_eq!(ChallengeLayout::permutations(2, 4), 1);
        assert_eq!(ChallengeLayout::permutations(4, 4), 1);
        assert_eq!(ChallengeLayout::permutations(5, 4), 2);
        assert_eq!(ChallengeLayout::permutations(8, 4), 2);
        // An odd rate still rounds up.
        assert_eq!(ChallengeLayout::permutations(4, 3), 2);
    }
}
