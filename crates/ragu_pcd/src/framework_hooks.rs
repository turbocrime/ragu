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
//!   [`NUM_POLY_QUERY_SLOTS`](crate::NUM_POLY_QUERY_SLOTS) claim slots as part
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
//!   most [`NUM_CHALLENGE_SLOTS`](crate::NUM_CHALLENGE_SLOTS) slots, each
//!   committing at most [`CHALLENGE_WIDTH`](crate::CHALLENGE_WIDTH) elements.
//!
//!   The derivation itself lives on [`StepCtx`](crate::step::StepCtx), not
//!   here, because it needs the whole [`Cycle`](ragu_arithmetic::Cycle) — host
//!   generators to commit the stage, nested generators to bridge it, and the
//!   circuit Poseidon to hash the result — while this container is
//!   parameterized only by the nested curve. Folding the `Cycle` in here and
//!   reuniting the two halves would be the tidier shape.
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
//! system has yet — so the chain reaches exactly the same parity as
//! `bridge_f` and no further. See `POLY_QUERY_SOUNDNESS.md`.
//!
//! The framework collects the resulting outputs through the adapter's `Aux` for
//! later fuse-time processing. New framework hooks (e.g. transcript threading)
//! belong on this type as well.
//!
//! [PCS aggregation]: https://tachyon.z.cash/ragu/protocol/core/accumulation/pcs.html#pcs-aggregation
//! [`Error::InvalidWitness`]: ragu_core::Error::InvalidWitness

use alloc::vec::Vec;

use ragu_arithmetic::{CurveAffine, ff::Field};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
};
use ragu_primitives::{Element, GadgetExt, Point};

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
pub struct FrameworkHooks<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    poly_query_claims: Vec<ClaimWires<'dr, D, C>>,
    /// Number of polynomials witnessed so far via
    /// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial).
    /// Assigns each claim its slot, which fixes the bridge stage — and
    /// therefore the generator positions — its `com` commits to.
    witnessed_claims: usize,
    /// The `(bridged stage commitment, challenge)` pair each
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge) call produced, in slot
    /// order.
    challenge_pairs: Vec<ChallengeWires<'dr, D, C>>,
    /// The values each challenge stage commits, in slot order.
    challenge_inputs: Vec<DriverValue<D, [D::F; crate::CHALLENGE_WIDTH]>>,
    /// Number of [`derive_challenge`](crate::step::StepCtx::derive_challenge) calls so far.
    /// Each occupies one of the
    /// [`NUM_CHALLENGE_SLOTS`](crate::NUM_CHALLENGE_SLOTS) slots; the widths
    /// need no recording, being compile-time constants of the input types.
    challenge_calls: usize,
    /// The call count discovered by the registration-time dry run, replayed as
    /// a per-call determinism guard. `None` in discovery mode (see the
    /// [module documentation](self)).
    expected_calls: Option<usize>,
}

/// Aggregate of every hook's accumulated output, returned by
/// [`FrameworkHooks::into_outputs`]. Adding a new hook means adding a field
/// here, which forces every drain site to acknowledge it.
pub struct FrameworkHookOutputs<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// Polynomial-commitment opening claims raised via
    /// [`FrameworkHooks::enforce_polynomial_query`], in call order — the
    /// in-circuit wires plus the witness-only coefficient values.
    pub poly_query_claims: Vec<ClaimWires<'dr, D, C>>,
    /// Number of [`StepCtx::derive_challenge`](crate::step::StepCtx::derive_challenge) calls. The
    /// registration-time dry run reads this to discover the call count; the
    /// adapter compares it against that count after real synthesis.
    pub challenge_calls: usize,
    /// The `(bridged commitment, challenge)` pair per `derive_challenge` call,
    /// in slot order.
    pub challenge_pairs: Vec<ChallengeWires<'dr, D, C>>,
    /// The values each challenge stage commits, in slot order.
    pub challenge_inputs: Vec<DriverValue<D, [D::F; crate::CHALLENGE_WIDTH]>>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> FrameworkHooks<'dr, D, C> {
    /// Creates a new, empty hook container in **discovery mode**: no expected
    /// call layout, so [`derive_challenge`](crate::step::StepCtx::derive_challenge) records
    /// input widths without checking them. Used by the registration-time dry
    /// run that discovers the call layout; real synthesis goes through
    /// [`with_expected`](Self::with_expected).
    pub fn new() -> Self {
        Self {
            poly_query_claims: Vec::new(),
            witnessed_claims: 0,
            challenge_calls: 0,
            challenge_pairs: Vec::new(),
            challenge_inputs: Vec::new(),
            expected_calls: None,
        }
    }

    /// Creates a hook container with the `derive_challenge` call count
    /// discovered at registration time. Each
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge) call is checked against it,
    /// so a body that makes more calls than the dry run did fails at the
    /// offending call.
    pub fn with_expected(expected_calls: usize) -> Self {
        Self {
            expected_calls: Some(expected_calls),
            ..Self::new()
        }
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
        if let Some(expected) = self.expected_calls
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
        point: Point<'dr, D, C>,
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
    /// [`NUM_POLY_QUERY_SLOTS`](crate::NUM_POLY_QUERY_SLOTS) instance slots,
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
        com: Point<'dr, D, C>,
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

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Default for FrameworkHooks<'dr, D, C> {
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
        let mut hooks = FrameworkHooks::<Dr<'_>, NestedCurve>::new();
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
        let mut hooks = FrameworkHooks::<Dr<'_>, NestedCurve>::with_expected(1);
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
