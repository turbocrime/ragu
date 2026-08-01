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
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{Element, allocator::Standard, vec::Len};

use crate::{
    internal::challenge::Padding,
    poly_commitment::{PolyCommitment, PolyHandle},
};

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
/// carries **these same wires** — a step's [`PolyHandle`] holds them, and
/// padding reads slot 0's back out — so the polynomial region and the claim
/// region hold one pair of wires at two instance positions and their equality
/// needs no constraint.
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
/// constructs this, passes it to the step, then drains it into a
/// [`FrameworkAux`] surfaced through its `Aux` for later fuse-time
/// processing.
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
    /// The application's declared slot capacities: what every circuit's
    /// instance exposes, what padding fills to, and what each hook checks
    /// calls against.
    hook_layout: HookLayout,
    /// The cycle anchors the output types ([`FrameworkAux`] is per-cycle);
    /// the hooks themselves hold no cycle data.
    _marker: core::marker::PhantomData<C>,
}

/// Every hook's output as plain values, for the fuse — what
/// [`FrameworkHooks::into_values`] drains the accumulated wires into.
///
/// A step circuit's `Aux` carries one of these beside the step's own `Aux`;
/// adding a hook means adding a field here, which the compiler forces every
/// drain site to acknowledge.
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
    pub claims: Vec<crate::proof::ClaimOpening<C::CircuitField>>,
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
/// type. Usually written as [`AppHooks`](crate::AppHooks) rather than
/// implemented by hand.
///
/// Each member is a [`Len`], so it slots directly into the `FixedVec`s the
/// framework sizes with it; the plain numbers are read back through
/// [`layout`](Self::layout).
///
/// [`PolyWitnesses`](Self::PolyWitnesses) is how many
/// [`witness_polynomial`](crate::step::StepCtx::witness_polynomial) slots
/// any one step may fill — the expensive axis: a bridge stage, a
/// commitment, an MSM, and an endoscaling point per child, each.
/// [`PolyQueries`](Self::PolyQueries) is how many
/// [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) claims
/// it may raise — the cheap axis: one instance triple, one `_08_f`
/// quotient, one `compute_v` triple. A repeat opening costs a claim slot
/// and no polynomial slot.
///
/// [`ChallengeDerivations`](Self::ChallengeDerivations) is how many
/// [`derive_challenge`](crate::step::StepCtx::derive_challenge) calls any
/// one step may make, and [`ChallengeWidth`](Self::ChallengeWidth) the
/// widest input one call may pass, in field elements — a
/// [`coords`](crate::PolyHandle::coords) pair is two; the width's cost is
/// `⌈width / rate⌉` sponge permutations, paid by the internal
/// `challenge_binding` circuit per `(child, slot)`.
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
    fn layout() -> HookLayout {
        HookLayout {
            challenge: ChallengeLayout {
                calls: Self::ChallengeDerivations::len(),
                width: Self::ChallengeWidth::len(),
            },
            poly_query: PolyQueryLayout {
                polys: Self::PolyWitnesses::len(),
                claims: Self::PolyQueries::len(),
            },
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
    /// `⌈width / rate⌉` sponge permutations in `challenge_binding`.
    pub width: usize,
}

impl ChallengeLayout {
    /// Instance elements the challenge slots occupy, per proof: each call's
    /// input elements, then the challenge itself.
    pub const fn instance_len(&self) -> usize {
        self.calls * (self.width + 1)
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

impl PolyQueryLayout {
    /// Instance elements the poly and claim slots occupy, per proof: the
    /// name pair per polynomial slot, and the name pair plus the $(x, y)$
    /// opening per claim slot.
    pub const fn instance_len(&self) -> usize {
        self.polys * 2 + self.claims * 4
    }
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> FrameworkHooks<'dr, D, C> {
    /// The witnessed polynomials' wires, in slot order.
    pub(crate) fn witnessed_polys(&self) -> &[PolyWires<'dr, D>] {
        &self.witnessed_polys
    }

    /// The raised claims' wires, in call order.
    pub(crate) fn poly_queries(&self) -> &[QueryWires<'dr, D>] {
        &self.poly_queries
    }

    /// The `(inputs, challenge)` wires per challenge slot, in slot order.
    pub(crate) fn challenge_pairs(&self) -> &[ChallengeWires<'dr, D>] {
        &self.challenge_pairs
    }

    /// Reads each hook's wires back out as plain values, for the fuse.
    pub(crate) fn into_values(self) -> Result<DriverValue<D, FrameworkAux<C>>> {
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
                Ok(crate::proof::ClaimOpening {
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

        // `finish_slots` padded each to the application's capacity.
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
    /// Creates a hook container at the application's declared `capacity`.
    ///
    /// There is one constructor because there is one pass. The capacity is
    /// declared, so nothing has to be learned from the step body first — each
    /// hook simply refuses a call past the capacity, at the call that exceeds
    /// it. Nothing else is needed: the hooks accumulate wires, and the two
    /// values the framework computes for them arrive from outside — the
    /// challenge hash through
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge)'s
    /// parameters argument, the padding constants through the witness
    /// channel.
    pub(crate) fn new(hook_layout: HookLayout) -> Self {
        Self {
            poly_queries: Vec::new(),
            witnessed_polys: Vec::new(),
            challenge_pairs: Vec::new(),
            hook_layout,
            _marker: core::marker::PhantomData,
        }
    }

    /// Witnesses the step's polynomials — the work behind
    /// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial),
    /// which documents the step-facing contract.
    pub(crate) fn witness_polynomials<R: Rank, const N: usize>(
        &mut self,
        dr: &mut D,
        commitments: [DriverValue<D, PolyCommitment<C, R>>; N],
    ) -> Result<[PolyHandle<'dr, D, C, R>; N]> {
        if !self.witnessed_polys.is_empty() {
            return Err(Error::InvalidWitness(
                "witness_polynomial may only be called once per step".into(),
            ));
        }

        let mut handles = Vec::with_capacity(N);
        for commitment in commitments {
            handles.push(self.witness_one_polynomial::<R>(dr, commitment)?);
        }

        // `N` handles were pushed, one per element of a `[_; N]`.
        Ok(handles
            .try_into()
            .map_err(|_| ())
            .expect("one handle per commitment"))
    }

    /// Witnesses one polynomial into the next free slot — also the per-slot
    /// door padding uses, past the step-facing array call's once-only rule.
    ///
    /// The call sequence is circuit structure — it must not depend on witness
    /// values — so the slot assignment is deterministic: call order.
    fn witness_one_polynomial<R: Rank>(
        &mut self,
        dr: &mut D,
        commitment: DriverValue<D, PolyCommitment<C, R>>,
    ) -> Result<PolyHandle<'dr, D, C, R>> {
        if self.witnessed_polys.len() >= self.hook_layout.poly_query.polys {
            return Err(Error::InvalidWitness(
                "step witnessed more polynomials than there are polynomial slots".into(),
            ));
        }
        // The slot's two coordinate instance wires: the commitment's
        // representation, and the value a consumer hashes or compares. Plain
        // value-filled wires, fail-closed: the accumulator and the root
        // recompute force them to be the recorded host's, or no proof
        // exists.
        let coord_values = commitment.as_ref().map(|c| c.coords());
        let coords = [
            Element::alloc(dr, &mut (), coord_values.as_ref().map(|c| c[0]))?,
            Element::alloc(dr, &mut (), coord_values.as_ref().map(|c| c[1]))?,
        ];
        let polynomial = commitment.map(PolyCommitment::into_polynomial);
        let handle = PolyHandle::new(polynomial, coords.clone());
        self.witnessed_polys.push(PolyWires {
            coefficients: handle.coefficients(),
            coords,
        });
        Ok(handle)
    }

    /// Records a claim that the polynomial named by `coords` evaluates to `y`
    /// at the point `x` — the sink behind
    /// [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query),
    /// which documents the step-facing contract. Padding reaches it directly,
    /// naming slot 0.
    ///
    /// The number of calls per step body is part of the circuit structure: it
    /// must not depend on witness values and must not exceed the application's
    /// claim capacity — checked here, at the call that exceeds it.
    pub(crate) fn enforce_poly_query(
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

    /// Derives a Fiat–Shamir challenge — the work behind
    /// [`StepCtx::derive_challenge`](crate::step::StepCtx::derive_challenge),
    /// which documents the step-facing contract and the caller's obligation.
    ///
    /// The `(inputs, challenge)` record accumulates here; the adapter writes
    /// it into the application circuit's public instance, binding it to its
    /// $k(Y)$ so the parent's binding circuit can re-derive the challenge
    /// from the inputs.
    pub(crate) fn derive_challenge(
        &mut self,
        dr: &mut D,
        params: &C::Params,
        inputs: &[Element<'dr, D>],
    ) -> Result<Element<'dr, D>> {
        let width = self.hook_layout.challenge.width;
        if inputs.len() > width {
            return Err(Error::InvalidWitness(
                "derive_challenge received more elements than a challenge slot absorbs".into(),
            ));
        }
        if self.challenge_pairs.len() >= self.hook_layout.challenge.calls {
            return Err(Error::InvalidWitness(
                "step derived more challenges than there are challenge slots".into(),
            ));
        }

        let supplied = D::try_just(|| {
            let mut values = Vec::with_capacity(inputs.len());
            for input in inputs {
                values.push(*input.value().take());
            }
            Ok(values)
        })?;

        // Pad to the slot's full complement with the sentinel and hash. The
        // padded inputs are witnessed like the supplied ones: the parent
        // absorbs a fixed number per slot, so it must see them all.
        let derived = D::try_just(|| {
            crate::internal::challenge::padded_challenge::<C>(params, &supplied.take(), width)
        })?;

        let allocator = &mut Standard::new();
        let mut witnessed = Vec::with_capacity(width);
        for index in 0..width {
            match inputs.get(index) {
                // A supplied element is already a wire in this circuit; reuse
                // it rather than re-witnessing, so the instance names the very
                // wire the caller pinned.
                Some(input) => witnessed.push(input.clone()),
                None => witnessed.push(Element::alloc(
                    dr,
                    allocator,
                    derived.as_ref().map(|(padded, _)| padded[index]),
                )?),
            }
        }

        let challenge = Element::alloc(dr, allocator, derived.map(|(_, challenge)| challenge))?;
        self.challenge_pairs.push(ChallengeWires {
            inputs: witnessed,
            challenge: challenge.clone(),
        });
        Ok(challenge)
    }

    /// Pads every slot the step body left unused, up to the application's
    /// declared capacity — the instance shape the internal circuits read as a
    /// fixed-width record. The adapter calls this after the step body
    /// returns; it is not step-facing, so it is not on
    /// [`StepCtx`](crate::step::StepCtx).
    ///
    /// Padding goes through the same doors a step body does
    /// ([`witness_one_polynomial`](Self::witness_one_polynomial),
    /// [`enforce_poly_query`](Self::enforce_poly_query), the challenge
    /// record), and the padded values are *real*: a trivially true claim (the
    /// constant polynomial $1$, opened at $0$ to $1$) and the challenge the
    /// sentinel points honestly hash to, so the parent's circuits treat every
    /// slot uniformly. The values themselves are the per-application
    /// constants of [`Padding`], computed at finalize and supplied as witness
    /// data — which is why padding, unlike
    /// [`derive_challenge`](Self::derive_challenge), needs no cycle
    /// parameters.
    ///
    /// `R` is a method parameter so the rank stays out of the container's
    /// type, and out of every `Step::witness` signature with it.
    pub(crate) fn finish_slots<R: Rank>(
        &mut self,
        dr: &mut D,
        padding: DriverValue<D, Padding<C, R>>,
    ) -> Result<()> {
        // Polynomials first, so every query slot has something to name. The
        // handle is discarded — the slot is recorded, and every padding query
        // names slot 0.
        while self.witnessed_polys.len() < self.hook_layout.poly_query.polys {
            let commitment = padding.as_ref().map(|p| p.poly.clone());
            self.witness_one_polynomial::<R>(dr, commitment)?;
        }

        // Then queries. Every padding query is the *same* query — slot 0
        // opened at $x = 0$, where the value is the constant term, true
        // whatever the slot holds — so it is witnessed once and its wires are
        // reused for every unused slot, keeping the step's circuit
        // independent of the claim capacity.
        let allocator = &mut Standard::new();
        let mut padding_query: Option<(Element<'dr, D>, Element<'dr, D>)> = None;
        while self.poly_queries.len() < self.hook_layout.poly_query.claims {
            let slot_zero = self.witnessed_polys.first().ok_or_else(|| {
                Error::InvalidWitness("a padding claim requires a polynomial slot to name".into())
            })?;
            let coords = slot_zero.coords.clone();
            let (x, y) = match &padding_query {
                Some((x, y)) => (x.clone(), y.clone()),
                None => {
                    let x = Element::alloc(dr, allocator, D::just(|| D::F::ZERO))?;
                    // Slot 0's value at zero is its constant term.
                    let y_value = slot_zero
                        .coefficients
                        .as_ref()
                        .map(|coefficients| coefficients.first().copied().unwrap_or(D::F::ZERO));
                    let y = Element::alloc(dr, allocator, y_value)?;
                    padding_query = Some((x.clone(), y.clone()));
                    (x, y)
                }
            };
            self.enforce_poly_query(coords, x, y)?;
        }

        // A padding challenge supplies no points at all: every input position
        // holds the sentinel and the challenge is their hash — both
        // per-application constants carried by `padding`. The allocation
        // pattern matches a `derive_challenge` call exactly (a fresh
        // allocator per slot, the inputs, then the challenge), so the circuit
        // is the same one the body would have produced.
        while self.challenge_pairs.len() < self.hook_layout.challenge.calls {
            let allocator = &mut Standard::new();
            let mut witnessed = Vec::with_capacity(self.hook_layout.challenge.width);
            for _ in 0..self.hook_layout.challenge.width {
                witnessed.push(Element::alloc(
                    dr,
                    allocator,
                    padding.as_ref().map(|p| p.sentinel),
                )?);
            }
            let challenge = Element::alloc(
                dr,
                allocator,
                padding.as_ref().map(|p| {
                    p.challenge
                        .expect("a padded challenge slot implies a nonzero challenge width")
                }),
            )?;
            self.challenge_pairs.push(ChallengeWires {
                inputs: witnessed,
                challenge,
            });
        }

        Ok(())
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
                challenge: ChallengeLayout { calls, width: 2 },
                poly_query: PolyQueryLayout::default(),
            })
        };
        let params = Pasta::baked();

        let mut dr: Dr<'_> = Emulator::counter();
        with_capacity(1)
            .derive_challenge(&mut dr, params, &[])
            .expect("a slot is available");

        let mut dr: Dr<'_> = Emulator::counter();
        let error = with_capacity(0)
            .derive_challenge(&mut dr, params, &[])
            .err()
            .expect("a step with no challenge slots cannot derive one");
        assert!(
            alloc::format!("{error}").contains("challenge slots"),
            "unexpected error: {error}"
        );
    }
}
