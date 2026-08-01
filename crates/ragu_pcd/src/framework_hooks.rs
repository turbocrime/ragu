//! Framework-side state surfaced to [`Step::witness`](crate::step::Step::witness) impls.
//!
//! [`FrameworkHooks`] accumulates the wires behind the hooks a step reaches
//! through [`StepCtx`](crate::step::StepCtx): the polynomial slots
//! ([`StepCtx::polys`](crate::step::StepCtx::polys)), the claim sink
//! ([`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query))
//! and the challenge slots
//! ([`StepCtx::derive_challenge`](crate::step::StepCtx::derive_challenge)) —
//! each documented where the step calls it. Every slot is part of the
//! application circuit's public instance, padded to the application's
//! declared capacity ([`HookLayout`]; the crate docs say why capacity is
//! declared), so every step of an application exposes one instance shape.
//! New framework hooks (e.g. transcript threading) belong here too.
//!
//! ## The binding chain
//!
//! A claim or challenge is enforced by the **parent**, from the instance:
//!
//! 1. Every slot's wires are written into the child's application $k(Y)$
//!    (the internal `preamble` stage's `application_ky`), binding them to
//!    its committed application rx.
//! 2. A claim is folded — the parent takes the quotient $(p(X) - y)/(X - x)$
//!    into $f(X)$, beta-accumulates $p(X)$ into the PCS $(P, u, v)$
//!    accumulator, and `compute_v` re-derives the matching terms from the
//!    instance-bound claim data. A challenge is re-derived —
//!    `challenge = Hash(inputs)` is enforced per `(child, slot)` by the
//!    internal `challenge_binding` circuit. A root proof's own slots, which
//!    no parent has bound, are checked natively by
//!    [`Application::verify`](crate::Application::verify).
//!
//! What remains beyond that is the framework-wide deferred PCS opening — the
//! commitment-to-carried-polynomial link that **no** commitment in the system
//! has yet, `bridge_f` and the endoscaling commitments included — so the
//! chain reaches exactly the parity of the framework's own bridges and no
//! further.

use alloc::vec::Vec;

use ragu_arithmetic::{Cycle, ff::Field};
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

/// The in-circuit wires of a derived challenge: the field elements it was
/// hashed from, and the challenge itself. All of them go into the application
/// circuit's public instance so the parent can re-derive the challenge from
/// the inputs.
pub struct ChallengeWires<'dr, D: Driver<'dr>> {
    /// The slot's input elements, exactly [`HookLayout::challenge_width`] of
    /// them: the caller's, then the sentinel in each position left empty.
    pub inputs: Vec<Element<'dr, D>>,
    /// The challenge, hashed from [`inputs`](Self::inputs).
    pub challenge: Element<'dr, D>,
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
    /// One entry per polynomial slot, in slot order — the very handles the
    /// step body reads via [`StepCtx::polys`](crate::step::StepCtx::polys),
    /// so the instance names the body's wires.
    witnessed_polys: Vec<PolyHandle<'dr, D, C>>,
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
    pub polys: Vec<PolyCommitment<C>>,
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
/// [`PolyWitnesses`](Self::PolyWitnesses) is how many polynomial slots
/// any one step may declare via
/// [`Step::polynomials`](crate::step::Step::polynomials) — the expensive
/// axis: a bridge stage, a commitment, an MSM, and an endoscaling point
/// per child, each.
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
            challenge_calls: Self::ChallengeDerivations::len(),
            challenge_width: Self::ChallengeWidth::len(),
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
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge) calls.
    pub challenge_calls: usize,
    /// Input field elements one challenge derivation absorbs. Every call's
    /// instance region holds exactly this many, with the positions a caller
    /// leaves empty taking a fixed sentinel.
    pub challenge_width: usize,
    /// Polynomial slots ([`Step::polynomials`](crate::step::Step::polynomials)
    /// declarations) — the expensive count.
    pub polys: usize,
    /// [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query)
    /// claims — the cheap count; a flat pool, so several claims can open one
    /// polynomial at the claim rate.
    pub claims: usize,
}

impl HookLayout {
    /// Instance elements the challenge slots occupy, per proof: each call's
    /// input elements, then the challenge itself.
    pub const fn challenge_instance_len(&self) -> usize {
        self.challenge_calls * (self.challenge_width + 1)
    }

    /// Instance elements the poly and claim slots occupy, per proof: the
    /// name pair per polynomial slot, and the name pair plus the $(x, y)$
    /// opening per claim slot.
    pub const fn poly_query_instance_len(&self) -> usize {
        self.polys * 2 + self.claims * 4
    }
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> FrameworkHooks<'dr, D, C> {
    /// The witnessed polynomials' handles, in slot order.
    pub(crate) fn witnessed_polys(&self) -> &[PolyHandle<'dr, D, C>] {
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
        for handle in self.witnessed_polys {
            let coefficients = handle.coefficients();
            let coords = handle.coords();
            polys.push(D::try_just(|| {
                Ok(PolyCommitment::from_parts(
                    coefficients.take(),
                    [*coords[0].value().take(), *coords[1].value().take()],
                ))
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
    /// Creates a hook container at the application's declared capacities;
    /// each hook refuses a call past its capacity, at the call that exceeds
    /// it.
    pub(crate) fn new(hook_layout: HookLayout) -> Self {
        Self {
            poly_queries: Vec::new(),
            witnessed_polys: Vec::new(),
            challenge_pairs: Vec::new(),
            hook_layout,
            _marker: core::marker::PhantomData,
        }
    }

    /// Witnesses every polynomial slot, before the step body runs: the
    /// step's declared commitments in declaration order, then the padding
    /// polynomial in each remaining slot. The body reaches the handles
    /// through [`StepCtx::polys`](crate::step::StepCtx::polys).
    ///
    /// The slot count is always the declared capacity, whatever the step
    /// supplies — the circuit shape must not depend on witness values.
    /// Declaring more than the capacity is a value-level error, caught
    /// while proving.
    pub(crate) fn witness_declared_polynomials(
        &mut self,
        dr: &mut D,
        declared: DriverValue<D, Vec<PolyCommitment<C>>>,
        padding: &DriverValue<D, Padding<C>>,
    ) -> Result<()> {
        let capacity = self.hook_layout.polys;
        D::try_just(|| {
            if declared.as_ref().take().len() > capacity {
                return Err(Error::InvalidWitness(
                    "step declared more polynomials than there are polynomial slots".into(),
                ));
            }
            Ok(())
        })?;
        for index in 0..capacity {
            let commitment = declared.as_ref().and_then(|list| {
                padding
                    .as_ref()
                    .map(|p| list.get(index).cloned().unwrap_or_else(|| p.poly.clone()))
            });
            self.witness_one_polynomial(dr, commitment)?;
        }
        Ok(())
    }

    /// Witnesses one polynomial into the next free slot.
    ///
    /// The call sequence is circuit structure — it must not depend on witness
    /// values — so the slot assignment is deterministic: call order.
    fn witness_one_polynomial(
        &mut self,
        dr: &mut D,
        commitment: DriverValue<D, PolyCommitment<C>>,
    ) -> Result<PolyHandle<'dr, D, C>> {
        if self.witnessed_polys.len() >= self.hook_layout.polys {
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
        let coefficients = commitment.map(PolyCommitment::into_coefficients);
        let handle = PolyHandle::new(coefficients, coords);
        self.witnessed_polys.push(handle.clone());
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
        if self.poly_queries.len() >= self.hook_layout.claims {
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
        let width = self.hook_layout.challenge_width;
        if inputs.len() > width {
            return Err(Error::InvalidWitness(
                "derive_challenge received more elements than a challenge slot absorbs".into(),
            ));
        }
        if self.challenge_pairs.len() >= self.hook_layout.challenge_calls {
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
    pub(crate) fn finish_slots(
        &mut self,
        dr: &mut D,
        padding: DriverValue<D, Padding<C>>,
    ) -> Result<()> {
        // The polynomial slots were all witnessed before the body ran
        // (`witness_declared_polynomials`), so only queries and challenges
        // remain. Queries first. Every padding query is the *same* query — slot 0
        // opened at $x = 0$, where the value is the constant term, true
        // whatever the slot holds — so it is witnessed once and its wires are
        // reused for every unused slot, keeping the step's circuit
        // independent of the claim capacity.
        let allocator = &mut Standard::new();
        let mut padding_query: Option<(Element<'dr, D>, Element<'dr, D>)> = None;
        while self.poly_queries.len() < self.hook_layout.claims {
            let slot_zero = self.witnessed_polys.first().ok_or_else(|| {
                Error::InvalidWitness("a padding claim requires a polynomial slot to name".into())
            })?;
            let coords = slot_zero.coords();
            let (x, y) = match &padding_query {
                Some((x, y)) => (x.clone(), y.clone()),
                None => {
                    let x = Element::alloc(dr, allocator, D::just(|| D::F::ZERO))?;
                    // Slot 0's value at zero is its constant term.
                    let y_value = slot_zero
                        .coefficients()
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
        while self.challenge_pairs.len() < self.hook_layout.challenge_calls {
            let allocator = &mut Standard::new();
            let mut witnessed = Vec::with_capacity(self.hook_layout.challenge_width);
            for _ in 0..self.hook_layout.challenge_width {
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
                challenge_calls: calls,
                challenge_width: 2,
                ..HookLayout::default()
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
