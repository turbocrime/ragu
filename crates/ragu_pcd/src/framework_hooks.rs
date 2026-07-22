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
//!   coefficients so that fuse can check the claim (and eventually batch it
//!   into the [PCS aggregation]). The framework enforces every recorded claim
//!   natively at fuse time: an evaluation claim that does not hold, or a
//!   commitment that does not bind the polynomial (see
//!   [`Application::commit_polynomial`](crate::Application::commit_polynomial)),
//!   aborts the fuse with [`Error::InvalidWitness`]. Folding the claims into
//!   the proof system's own $(P, u, v)$ accumulator — so that the *merge
//!   circuit* enforces them recursively rather than the native prover — is
//!   tracked as future work; it requires matching poly-query slots in the
//!   `compute_v` circuit and the nested endoscaling chain.
//!
//! * [`derive_challenge`](FrameworkHooks::derive_challenge) — derives a
//!   Fiat–Shamir challenge from any [`ChallengeInput`] as the **in-circuit
//!   Poseidon sponge hash** of the input's elements. The squeezed challenge
//!   wire is constrained to equal that hash, so the derivation is *sound*:
//!   within the proof system's guarantees, a prover cannot pick the challenge
//!   independently of the input. Each call also *induces a stage*: the input's
//!   wires are recorded as a partial-trace layout so that a future `fuse()`
//!   optimization can commit to each stage independently and derive the
//!   challenge from the *succinct* commitment (hashed in a fixed internal
//!   circuit, à la `internal/native/circuits/hashes_1.rs`) instead of paying
//!   for the sponge in the application circuit. The simple model is one stage
//!   per call; batching consecutive calls into a single stage is part of the
//!   same future optimization. See [`InducedStage`].
//!
//! ## Induced stage layout
//!
//! The stages induced by `derive_challenge` are not known at Rust compile
//! time — they depend on how many calls the step body makes and how wide each
//! input is. They *are* known at registration time, because circuit structure
//! is witness-independent: the adapter dry-runs the step body once (with an
//! [`Empty`](ragu_core::maybe::Empty) witness, on a counting emulator) and
//! records each call's input width, producing an
//! [`InducedStages`](ragu_circuits::staging::InducedStages) layout. The
//! adapter then reserves one region per stage at the head of the trace before
//! running the body for real, and passes the reserved regions to this
//! container via [`with_reserved`](FrameworkHooks::with_reserved). Each
//! `derive_challenge` call binds its input into the next reserved region with
//! one equality constraint per wire — that copy is what makes the stage
//! commitment (and hence the challenge) binding.
//!
//! A container created with [`new`](FrameworkHooks::new) has no reservations
//! and performs no binding: that is **discovery mode**, used only for the
//! registration-time dry run that produces the layout in the first place.
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
    gadgets::Gadget,
    maybe::Maybe,
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

/// A single stage induced by a [`FrameworkHooks::derive_challenge`] call.
///
/// Under the simple model there is exactly one stage per call: the wires of the
/// input handed to `derive_challenge` become this stage's partial-trace
/// polynomial, which a future `fuse()` optimization will commit to
/// independently so the challenge can be re-derived from a *succinct*
/// commitment instead of re-hashing the input. Today the challenge is the
/// in-circuit Poseidon hash of the input itself (sound, not yet succinct),
/// and the recorded stage layout is what keeps the trace shape
/// forward-compatible with that optimization.
pub struct InducedStage<'dr, D: Driver<'dr>> {
    /// Width of this stage's trace slice (the input's wire count) — the same
    /// quantity the registration-time discovery pass records in the
    /// [`InducedStages`](ragu_circuits::staging::InducedStages) layout, and
    /// the quantity the per-call determinism guard checks against it.
    pub num_wires: usize,
    /// The input's actual wire handles, in canonical traversal order, captured
    /// via [`ChallengeInput::append_elements`]. Always
    /// `wires.len() == num_wires`.
    pub wires: Vec<D::Wire>,
    /// The challenge handed back to the step body — the in-circuit Poseidon
    /// sponge hash of the input's elements.
    pub challenge: Element<'dr, D>,
}

/// Container for framework-side state threaded through a
/// [`Step::witness`](crate::step::Step::witness) invocation.
///
/// Holds the polynomial-commitment opening-claim sink and the stages induced by
/// [`derive_challenge`](Self::derive_challenge) calls. The framework's adapter
/// constructs this, passes it to the step, then surfaces
/// [`into_outputs`](Self::into_outputs) through its `Aux` for later fuse-time
/// processing.
pub struct FrameworkHooks<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    poly_query_claims: Vec<DriverValue<D, PolyQueryClaim<D::F, C>>>,
    /// Stages induced by [`FrameworkHooks::derive_challenge`] calls — one per
    /// call under the simple model. Tracked here so a future `fuse()`
    /// optimization can commit to each partial trace.
    derived_challenges: Vec<InducedStage<'dr, D>>,
    /// The reserved stage regions, one per induced stage in the layout
    /// discovered at registration time, in stage order. `None` in discovery
    /// mode (see the [module documentation](self)).
    reserved: Option<Vec<Vec<D::Wire>>>,
}

/// Aggregate of every hook's accumulated output, returned by
/// [`FrameworkHooks::into_outputs`]. Adding a new hook means adding a field
/// here, which forces every drain site to acknowledge it.
pub struct FrameworkHookOutputs<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// Polynomial-commitment opening claims raised via
    /// [`FrameworkHooks::enforce_polynomial_query`], with their polynomials.
    pub poly_query_claims: DriverValue<D, Vec<PolyQueryClaim<D::F, C>>>,
    /// Stages induced by [`FrameworkHooks::derive_challenge`] calls, in call
    /// order. Each carries the input's wire slice plus the challenge handle.
    /// A future `fuse()` optimization consumes these to build the per-call
    /// partial traces.
    pub derived_challenges: Vec<InducedStage<'dr, D>>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> FrameworkHooks<'dr, D, C> {
    /// Creates a new, empty hook container in **discovery mode**: no stage
    /// regions are reserved and [`derive_challenge`](Self::derive_challenge)
    /// only records input widths without binding them. Used by the
    /// registration-time dry run that discovers the induced stage layout; real
    /// synthesis goes through [`with_reserved`](Self::with_reserved).
    pub fn new() -> Self {
        Self {
            poly_query_claims: Vec::new(),
            derived_challenges: Vec::new(),
            reserved: None,
        }
    }

    /// Creates a hook container with the reserved stage regions for the
    /// induced stage layout discovered at registration time, one region per
    /// stage in stage order. Each [`derive_challenge`](Self::derive_challenge)
    /// call consumes the next region, binding the input's wires to it.
    pub fn with_reserved(reserved: Vec<Vec<D::Wire>>) -> Self {
        Self {
            poly_query_claims: Vec::new(),
            derived_challenges: Vec::new(),
            reserved: Some(reserved),
        }
    }

    /// Records a claim that the polynomial with the given `coefficients`
    /// (little-endian), committed to by `com`, evaluates to `y` at the point
    /// `x`.
    ///
    /// The claim is checked natively at fuse time: the framework re-evaluates
    /// the polynomial at `x` and recomputes the binding commitment (see
    /// [`Application::commit_polynomial`](crate::Application::commit_polynomial));
    /// a mismatch aborts the fuse with
    /// [`Error::InvalidWitness`].
    pub fn enforce_polynomial_query(
        &mut self,
        _dr: &mut D,
        com: Point<'dr, D, C>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
        coefficients: DriverValue<D, Vec<D::F>>,
    ) -> Result<()> {
        let claim = D::try_just(|| {
            Ok(PolyQueryClaim {
                com: com.value().take(),
                x: *x.value().take(),
                y: *y.value().take(),
                coefficients: coefficients.take(),
            })
        })?;
        self.poly_query_claims.push(claim);
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
    /// Each call also induces one stage (simple model: one stage per call):
    /// the input's wires are recorded as a partial-trace layout so that a
    /// future `fuse()` optimization can commit to them independently and
    /// re-derive the challenge from the *succinct* commitment instead of
    /// re-hashing the input in-circuit; see [`InducedStage`] and the
    /// [module documentation](self).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`] if the call sequence diverges from
    /// the layout discovered at registration time — more calls than discovered
    /// stages, or an input whose width differs from the discovered width. An
    /// honest step body cannot trip this: circuit structure must not depend on
    /// witness values, so the dry run and the real run make identical calls.
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
        // Capture the input's elements and wire handles now — the stage's
        // partial trace carries exactly these values.
        let mut elements = Vec::new();
        input.append_elements(dr, &mut elements)?;
        let mut wires = Vec::new();
        for element in &elements {
            wires.extend(element.collect_wires()?);
        }

        // Check the call against its reserved stage region. Skipped in
        // discovery mode, which only records widths.
        if let Some(reserved) = &self.reserved {
            let stage = self.derived_challenges.len();
            let region = reserved.get(stage).ok_or_else(|| {
                Error::InvalidWitness(
                    "derive_challenge called more times than the discovered stage layout; \
                     circuit structure must not depend on witness values"
                        .into(),
                )
            })?;
            if region.len() != wires.len() {
                return Err(Error::InvalidWitness(
                    "derive_challenge input width diverged from the discovered stage layout; \
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

        // Record the induced stage for the future succinct-commitment path.
        self.derived_challenges.push(InducedStage {
            num_wires: wires.len(),
            wires,
            challenge: challenge.clone(),
        });

        Ok(challenge)
    }

    /// Consumes the container and returns every hook's accumulated output.
    pub fn into_outputs(self) -> FrameworkHookOutputs<'dr, D, C> {
        let poly_query_claims =
            self.poly_query_claims
                .into_iter()
                .fold(D::just(Vec::new), |acc, claim| {
                    acc.and_then(|mut v| {
                        claim.map(|c| {
                            v.push(c);
                            v
                        })
                    })
                });
        FrameworkHookOutputs {
            poly_query_claims,
            derived_challenges: self.derived_challenges,
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

    /// A `derive_challenge` call records one induced stage per call with the
    /// input's wire count, on a structure-only driver.
    #[test]
    fn derive_challenge_records_stage_layout() {
        let pasta = Pasta::baked();
        let mut dr = Emulator::counter();
        let allocator = &mut Standard::new();
        let mut hooks = FrameworkHooks::<_, NestedCurve>::new();

        let a = Element::alloc(&mut dr, allocator, Empty).expect("alloc a");
        let b = Element::alloc(&mut dr, allocator, Empty).expect("alloc b");
        // Two-element input -> one induced stage of width 2.
        let _challenge = hooks
            .derive_challenge(&mut dr, Pasta::circuit_poseidon(pasta), (a, b))
            .expect("derive_challenge");

        let outputs = hooks.into_outputs();
        assert_eq!(outputs.derived_challenges.len(), 1);
        assert_eq!(outputs.derived_challenges[0].num_wires, 2);
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
