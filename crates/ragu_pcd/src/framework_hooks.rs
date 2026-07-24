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
//! * [`derive_challenge`](FrameworkHooks::derive_challenge) — derives a
//!   Fiat–Shamir challenge from any [`ChallengeInput`] as the **in-circuit
//!   Poseidon sponge hash** of the input's elements. The squeezed challenge
//!   wire is constrained to equal that hash, so the derivation is *sound*:
//!   within the proof system's guarantees, a prover cannot pick the challenge
//!   independently of the input.
//!
//! ## Structure discovery
//!
//! How many times a step body calls each hook — and how wide each
//! `derive_challenge` input is — is part of the circuit's structure, so it
//! must be witness-independent. The adapter dry-runs the step body once at
//! registration time (with an [`Empty`](ragu_core::maybe::Empty) witness, on a
//! counting emulator) with a container created by [`new`](FrameworkHooks::new)
//! (**discovery mode**), recording each `derive_challenge` call's input width
//! and the poly-query claim count. Real synthesis goes through
//! [`with_expected`](FrameworkHooks::with_expected), which replays the
//! discovered widths as a per-call determinism guard: a body whose call
//! sequence diverges from the dry run fails with
//! [`Error::InvalidWitness`] instead of silently synthesizing a different
//! circuit.
//!
//! ## Challenge soundness
//!
//! The challenge is computed by an in-circuit sponge, so on a value-carrying
//! driver the returned `Element` holds the real challenge value at the moment
//! of the call — the step body can immediately use it (e.g. to evaluate a
//! polynomial at it and enforce the evaluation) — while on structure-only
//! drivers the same sponge synthesizes the constraints that make the
//! derivation binding. There is no native side-channel to trust: the hash the
//! prover computes is the hash the circuit enforces.
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
use ragu_primitives::{Element, GadgetExt, Point, poseidon::Sponge};

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

/// An input to [`derive_challenge`](FrameworkHooks::derive_challenge): a
/// bundle of in-circuit data exposed as a canonical sequence of [`Element`]s.
/// The challenge is a Poseidon sponge hash over exactly this sequence,
/// computed *in-circuit*, so it is sound: the squeezed challenge wire is
/// constrained to be the hash of the input's wires.
///
/// Implemented for [`Element`], [`Point`], and homogeneous/heterogeneous
/// compositions of these (tuples, arrays, slices, and `Vec`s).
pub trait ChallengeInput<'dr, D: Driver<'dr>> {
    /// Appends this input's elements, in canonical order.
    fn append_elements(&self, dr: &mut D, out: &mut Vec<Element<'dr, D>>) -> Result<()>;
}

impl<'dr, D: Driver<'dr>> ChallengeInput<'dr, D> for Element<'dr, D> {
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
    fn append_elements(&self, dr: &mut D, out: &mut Vec<Element<'dr, D>>) -> Result<()> {
        (*self).append_elements(dr, out)
    }
}

impl<'dr, D: Driver<'dr>, T: ChallengeInput<'dr, D>, const N: usize> ChallengeInput<'dr, D>
    for [T; N]
{
    fn append_elements(&self, dr: &mut D, out: &mut Vec<Element<'dr, D>>) -> Result<()> {
        for item in self {
            item.append_elements(dr, out)?;
        }
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>, T: ChallengeInput<'dr, D>> ChallengeInput<'dr, D> for &[T] {
    fn append_elements(&self, dr: &mut D, out: &mut Vec<Element<'dr, D>>) -> Result<()> {
        for item in *self {
            item.append_elements(dr, out)?;
        }
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>, T: ChallengeInput<'dr, D>> ChallengeInput<'dr, D> for Vec<T> {
    fn append_elements(&self, dr: &mut D, out: &mut Vec<Element<'dr, D>>) -> Result<()> {
        for item in self {
            item.append_elements(dr, out)?;
        }
        Ok(())
    }
}

macro_rules! impl_challenge_input_tuple {
    ($($name:ident),+) => {
        impl<'dr, D: Driver<'dr>, $($name: ChallengeInput<'dr, D>),+> ChallengeInput<'dr, D>
            for ($($name,)+)
        {
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
/// [`derive_challenge`](Self::derive_challenge) calls. The framework's adapter
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
    /// Input width (element count) of each
    /// [`derive_challenge`](Self::derive_challenge) call, in call order.
    challenge_widths: Vec<usize>,
    /// The widths discovered by the registration-time dry run, replayed as a
    /// per-call determinism guard. `None` in discovery mode (see the
    /// [module documentation](self)).
    expected_widths: Option<Vec<usize>>,
}

/// Aggregate of every hook's accumulated output, returned by
/// [`FrameworkHooks::into_outputs`]. Adding a new hook means adding a field
/// here, which forces every drain site to acknowledge it.
pub struct FrameworkHookOutputs<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// Polynomial-commitment opening claims raised via
    /// [`FrameworkHooks::enforce_polynomial_query`], in call order — the
    /// in-circuit wires plus the witness-only coefficient values.
    pub poly_query_claims: Vec<ClaimWires<'dr, D, C>>,
    /// Input width (element count) of each
    /// [`FrameworkHooks::derive_challenge`] call, in call order. The
    /// registration-time dry run reads this to discover the call layout; the
    /// adapter compares its length against that layout after real synthesis.
    pub challenge_widths: Vec<usize>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> FrameworkHooks<'dr, D, C> {
    /// Creates a new, empty hook container in **discovery mode**: no expected
    /// call layout, so [`derive_challenge`](Self::derive_challenge) records
    /// input widths without checking them. Used by the registration-time dry
    /// run that discovers the call layout; real synthesis goes through
    /// [`with_expected`](Self::with_expected).
    pub fn new() -> Self {
        Self {
            poly_query_claims: Vec::new(),
            witnessed_claims: 0,
            challenge_widths: Vec::new(),
            expected_widths: None,
        }
    }

    /// Creates a hook container with the `derive_challenge` call layout
    /// discovered at registration time — one input width per call, in call
    /// order. Each [`derive_challenge`](Self::derive_challenge) call is
    /// checked against the next entry.
    pub fn with_expected(expected_widths: Vec<usize>) -> Self {
        Self {
            poly_query_claims: Vec::new(),
            witnessed_claims: 0,
            challenge_widths: Vec::new(),
            expected_widths: Some(expected_widths),
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
    pub fn enforce_polynomial_query(
        &mut self,
        _dr: &mut D,
        com: Point<'dr, D, C>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
        coefficients: DriverValue<D, Vec<D::F>>,
    ) -> Result<()> {
        self.poly_query_claims.push(ClaimWires {
            com,
            x,
            y,
            coefficients,
        });
        Ok(())
    }

    /// Derives a Fiat–Shamir challenge from `input`: the in-circuit Poseidon
    /// sponge hash of the input's elements. The squeezed challenge wire is
    /// *constrained* to be that hash, so the derivation is sound — a prover
    /// cannot choose the challenge independently of the input — and on a
    /// value-carrying driver the returned `Element` holds the real challenge
    /// value immediately, so the step body can evaluate polynomials at it
    /// right away.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`] if the call sequence diverges from
    /// the layout discovered at registration time — more calls than
    /// discovered, or an input whose width differs from the discovered width.
    /// An honest step body cannot trip this: circuit structure must not depend
    /// on witness values, so the dry run and the real run make identical
    /// calls.
    pub fn derive_challenge<G, P>(
        &mut self,
        dr: &mut D,
        poseidon: &'dr P,
        input: G,
    ) -> Result<Element<'dr, D>>
    where
        G: ChallengeInput<'dr, D>,
        P: ragu_arithmetic::PoseidonPermutation<D::F>,
    {
        let mut elements = Vec::new();
        input.append_elements(dr, &mut elements)?;

        // Determinism guard: check the call against the discovered layout.
        // Skipped in discovery mode, which only records widths.
        if let Some(expected) = &self.expected_widths {
            let call = self.challenge_widths.len();
            let width = expected.get(call).ok_or_else(|| {
                Error::InvalidWitness(
                    "derive_challenge called more times than the discovered call layout; \
                     circuit structure must not depend on witness values"
                        .into(),
                )
            })?;
            if *width != elements.len() {
                return Err(Error::InvalidWitness(
                    "derive_challenge input width diverged from the discovered call layout; \
                     circuit structure must not depend on witness values"
                        .into(),
                ));
            }
        }

        // Sound Fiat–Shamir: hash the input in-circuit. The constraint system
        // ties the squeezed challenge to the absorbed wires on every driver.
        let mut sponge = Sponge::new(dr, poseidon);
        for element in &elements {
            sponge.absorb(dr, element)?;
        }
        let challenge = sponge.squeeze(dr)?;

        self.challenge_widths.push(elements.len());

        Ok(challenge)
    }

    /// Consumes the container and returns every hook's accumulated output.
    pub fn into_outputs(self) -> FrameworkHookOutputs<'dr, D, C> {
        FrameworkHookOutputs {
            poly_query_claims: self.poly_query_claims,
            challenge_widths: self.challenge_widths,
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
    use ragu_arithmetic::{Cycle, ff::Field as _};
    use ragu_core::{
        drivers::emulator::Emulator,
        maybe::{Always, Empty, Maybe as _, MaybeKind},
    };
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::allocator::Standard;

    use super::*;

    type NestedCurve = <Pasta as Cycle>::NestedCurve;

    /// A `derive_challenge` call records the input's element width, in call
    /// order, on a structure-only driver.
    #[test]
    fn derive_challenge_records_call_layout() {
        let pasta = Pasta::baked();
        let mut dr = Emulator::counter();
        let allocator = &mut Standard::new();
        let mut hooks = FrameworkHooks::<_, NestedCurve>::new();

        let a = Element::alloc(&mut dr, allocator, Empty).expect("alloc a");
        let b = Element::alloc(&mut dr, allocator, Empty).expect("alloc b");
        // Two-element input -> one recorded call of width 2.
        let _challenge = hooks
            .derive_challenge(&mut dr, Pasta::circuit_poseidon(pasta), (a, b))
            .expect("derive_challenge");

        let outputs = hooks.into_outputs();
        assert_eq!(outputs.challenge_widths, alloc::vec![2]);
    }

    /// On a value-carrying driver the challenge resolves immediately, is
    /// deterministic in the input values, and distinct inputs yield distinct
    /// challenges.
    #[test]
    fn derive_challenge_is_deterministic_and_binding() {
        let pasta = Pasta::baked();

        let challenge_for = |x: u64, y: u64| -> Fp {
            let mut dr = Emulator::execute();
            let allocator = &mut Standard::new();
            let mut hooks = FrameworkHooks::<_, NestedCurve>::new();
            let a = Element::alloc(&mut dr, allocator, Always::maybe_just(|| Fp::from(x)))
                .expect("alloc a");
            let b = Element::alloc(&mut dr, allocator, Always::maybe_just(|| Fp::from(y)))
                .expect("alloc b");
            let challenge = hooks
                .derive_challenge(&mut dr, Pasta::circuit_poseidon(pasta), (a, b))
                .expect("derive_challenge");
            *challenge.value().take()
        };

        let c1 = challenge_for(3, 5);
        let c2 = challenge_for(3, 5);
        let c3 = challenge_for(3, 6);
        assert_eq!(c1, c2);
        assert_ne!(c1, c3);
        assert!(!bool::from(c1.is_zero()));
    }
}
