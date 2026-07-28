use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    registry::RegistryBuilder,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Bound, Kind},
    maybe::{Empty, Maybe},
};
use ragu_primitives::{
    Element, GadgetExt,
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

use super::super::{Step, StepCtx};
use crate::{
    CHALLENGE_POINTS_PER_CALL, Header, NUM_CHALLENGE_SLOTS, NUM_POLY_SLOTS, NUM_QUERY_SLOTS,
    framework_hooks::{
        Alphas, ChallengeLayout, FrameworkAux, FrameworkHooks, HookLayout, PolyQueryLayout,
        ProofValues,
    },
};

/// Length of an application circuit's public instance: the three headers, then
/// the polynomial slots (commitment point coordinates — two elements per slot),
/// then the query slots (the polynomial index and the $(x, y)$ opening — three
/// elements per slot), then the challenge slots (the coordinates of every input
/// point, then the challenge).
///
/// A polynomial's commitment appears once, in its own slot, rather than once
/// per query that opens it. That is what makes a repeat opening cost three
/// elements instead of a whole polynomial's worth — and it is also what makes
/// it *sound*: a query names its polynomial by index, so there is no second
/// copy of `com` that could disagree with the first.
pub struct InstanceLen<const HEADER_SIZE: usize>;

impl<const HEADER_SIZE: usize> Len for InstanceLen<HEADER_SIZE> {
    fn len() -> usize {
        HEADER_SIZE * 3
            + NUM_POLY_SLOTS * 2
            + NUM_QUERY_SLOTS * 3
            + NUM_CHALLENGE_SLOTS * (CHALLENGE_POINTS_PER_CALL * 2 + 1)
    }
}

/// Discovers the hook-call counts of `step` — how many
/// [`derive_challenge`](StepCtx::derive_challenge) calls it makes and how many
/// poly-query claims it raises — by dry-running its witness body once, with an
/// [`Empty`] witness on a counting emulator and the hooks in discovery mode.
///
/// Only call counts: how many points a `derive_challenge` call passes is
/// witness data (every slot's instance region is the same width regardless),
/// and a claim's wires are a fixed shape.
///
/// This is sound because circuit structure must be witness-independent: the
/// same body runs with `Empty` witnesses for wiring extraction and metrics,
/// so the call sequence cannot differ between this dry run and real
/// synthesis. (A body that violates that requirement is caught at synthesis
/// time by the determinism guard in [`StepCtx::derive_challenge`].)
pub(crate) fn discover_hook_layout<C: Cycle, S: Step<C>, const HEADER_SIZE: usize>(
    step: &S,
) -> Result<HookLayout> {
    let mut dr: Emulator<Wireless<Empty, C::CircuitField>> = Emulator::counter();
    let mut hooks = FrameworkHooks::<_, C>::new();
    {
        let mut ctx = StepCtx::<'_, '_, _, C>::new(&mut dr, &mut hooks);
        step.witness::<_, HEADER_SIZE>(&mut ctx, Empty, Empty, Empty)?;
    }

    let outputs = hooks.into_outputs();

    // No cap is applied here. The counts a step needs *are* its requirement;
    // the application's capacity is the maximum over its registered steps,
    // settled in `ApplicationBuilder::finalize` where the gate budget is known.
    // Checking against a framework constant here would reject a step the
    // application could afford, and would charge every other step for slots it
    // does not use.
    Ok(HookLayout {
        challenge: ChallengeLayout {
            calls: outputs.challenge_calls,
        },
        poly_query: PolyQueryLayout {
            polys: outputs.witnessed_polys.len(),
            claims: outputs.poly_queries.len(),
        },
    })
}

/// Auxiliary data produced by [`Adapter::witness`]: the two input headers, the
/// output data carried by the resulting PCD, the inner step's own aux, and the
/// polynomial-query claims raised by the step (checked and recorded by fuse —
/// see [`FrameworkHooks`]).
pub(crate) struct AdapterAux<'source, C: Cycle, S: Step<C>, const HEADER_SIZE: usize> {
    pub left_header: FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
    pub right_header: FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
    pub output_data: <S::Output as Header<C::CircuitField>>::Data,
    pub step_aux: S::Aux<'source>,
    /// Every framework hook's output, as one named group beside the step's own
    /// aux. See [`FrameworkAux`].
    pub framework: FrameworkAux<C>,
}

pub(crate) struct Adapter<'params, C: Cycle, S, R: Rank, const HEADER_SIZE: usize> {
    step: S,
    /// The hook-call counts discovered from the step's witness body at
    /// construction time; see [`discover_hook_layout`]. Part of the circuit
    /// structure, so synthesis replays them as a determinism guard — enforced
    /// by [`StepCtx::finish_slots`], not here.
    layout: HookLayout,
    /// The cycle's runtime parameters, absent during registration.
    ///
    /// `ApplicationBuilder::register` runs before
    /// [`finalize`](crate::ApplicationBuilder::finalize) supplies them, and it
    /// only needs the circuit's *structure*: the layout dry run above is
    /// structure-only, and the parameters are read solely to build a proof's
    /// witness values. So registration passes `None`, and the one place that
    /// reads them — [`witness`](MultiStageCircuit::witness) — does so inside a
    /// `try_just` that a structure-only driver discards.
    params: Option<&'params C::Params>,
    _marker: PhantomData<(C, R)>,
}

impl<'params, C: Cycle, S: Step<C>, R: Rank, const HEADER_SIZE: usize>
    Adapter<'params, C, S, R, HEADER_SIZE>
{
    /// Wraps `step` for registration/keygen, discovering its `derive_challenge`
    /// call count and poly-query claim count with a dry run of the witness
    /// body (see [`discover_hook_layout`]).
    ///
    /// The only constructor. `params` is `None` at registration, which runs
    /// before the cycle parameters exist and needs only the circuit's
    /// structure; see the field's documentation.
    pub fn new(step: S, params: Option<&'params C::Params>) -> Result<Self> {
        let layout = discover_hook_layout::<C, S, HEADER_SIZE>(&step)?;
        Ok(Adapter {
            step,
            layout,
            params,
            _marker: PhantomData,
        })
    }

    /// The number of [`derive_challenge`](StepCtx::derive_challenge) calls the
    /// step body makes.
    #[cfg(test)]
    pub fn challenge_calls(&self) -> usize {
        self.layout.challenge.calls
    }

    /// The step's discovered hook layout — its plan.
    pub(crate) fn layout(&self) -> HookLayout {
        self.layout
    }
}

/// An application step adapter held between
/// [`register`](crate::ApplicationBuilder::register) and
/// [`finalize`](crate::ApplicationBuilder::finalize).
///
/// Construction — including the hook-discovery dry run — happens at
/// `register`, but handing a circuit to the registry *measures* it: the
/// registry synthesizes the circuit and freezes its shape on the spot. A step
/// circuit's padded shape depends on the maximum slot counts over every
/// registered step, a value that is settled only once registration closes. So
/// the builder holds each adapter behind this trait and hands them all over in
/// `finalize`, after the last step has contributed to the maximum.
///
/// One method, because [`Circuit`](ragu_circuits::Circuit) is not object-safe
/// and the builder needs to hold adapters for differing `Step` types in one
/// collection.
pub(crate) trait PendingStep<'params, C: Cycle, R: Rank> {
    /// The held step's discovered hook layout — its plan, available before
    /// hand-over so `finalize` can settle the application's shape set first.
    fn layout(&self) -> HookLayout;

    /// Hands the adapter to the registry, measuring its circuit now.
    fn register(
        self: Box<Self>,
        registry: RegistryBuilder<'params, C::CircuitField, R>,
    ) -> Result<RegistryBuilder<'params, C::CircuitField, R>>;
}

impl<'params, C: Cycle, S: Step<C> + 'params, R: Rank, const HEADER_SIZE: usize>
    PendingStep<'params, C, R> for Adapter<'params, C, S, R, HEADER_SIZE>
{
    fn layout(&self) -> HookLayout {
        Adapter::layout(self)
    }

    fn register(
        self: Box<Self>,
        registry: RegistryBuilder<'params, C::CircuitField, R>,
    ) -> Result<RegistryBuilder<'params, C::CircuitField, R>> {
        registry.register_circuit(MultiStage::new(*self))
    }
}

impl<C: Cycle, S: Step<C> + Send + Sync, R: Rank, const HEADER_SIZE: usize>
    MultiStageCircuit<C::CircuitField, R> for Adapter<'_, C, S, R, HEADER_SIZE>
{
    /// An application circuit has no stages. Challenge derivation used to need
    /// one per slot — a committed partial trace to compress the inputs into —
    /// but a challenge input is a point, which is already a commitment, so
    /// there is nothing left to stage.
    type Last = ();
    type Instance<'source> = (
        FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        <S::Output as Header<C::CircuitField>>::Data,
    );
    type Witness<'source> = (
        Alphas<C>,
        <S::Left as Header<C::CircuitField>>::Data,
        <S::Right as Header<C::CircuitField>>::Data,
        S::Witness<'source>,
    );
    type Output = Kind![C::CircuitField; FixedVec<Element<'_, _>, InstanceLen<HEADER_SIZE>>];
    type Aux<'source> = AdapterAux<'source, C, S, HEADER_SIZE>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        unreachable!("k(Y) is computed manually for ragu_pcd circuit implementations")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let dr = builder.finish();

        let (alphas, left, right, witness) = witness.cast();
        // `Self: 'dr` gives `'params: 'dr`, so the parameters coerce. The
        // closure runs only on a value-carrying driver, and every such driver
        // is building a proof — which only `Application` can do, and only with
        // the parameters it was finalized against. Registration, the one pass
        // built with `None`, is structure-only, so `Empty::try_just` discards
        // this without calling it.
        let params = self.params;
        let proof_values = D::try_just(move || {
            let params = params.ok_or_else(|| {
                ragu_core::Error::InvalidWitness(
                    "step witnessed with proof blinds but no cycle parameters".into(),
                )
            })?;
            let alphas = alphas.take();
            Ok(ProofValues::new(params, alphas.bridge))
        })?;

        let mut hooks = FrameworkHooks::with_expected(self.layout, Maybe::clone(&proof_values));
        let ((left, right, output), output_data, step_aux) = {
            let mut ctx = StepCtx::<'_, '_, _, C>::new(dr, &mut hooks);
            let body = self
                .step
                .witness::<_, HEADER_SIZE>(&mut ctx, witness, left, right)?;
            // Check the body against the discovered layout and fill whatever
            // slots it left over, through the same hooks it used.
            ctx.finish_slots::<R>()?;
            body
        };
        let outputs = hooks.into_outputs();

        let mut elements = Vec::with_capacity(InstanceLen::<HEADER_SIZE>::len());
        left.write(dr, &mut elements)?;
        right.write(dr, &mut elements)?;
        output.write(dr, &mut elements)?;
        // The polynomial slots follow the headers: per slot, the commitment
        // point's two coordinates. Then the query slots: per slot, the index of
        // the polynomial opened, the opening point, and the claimed evaluation.
        // This layout must match `ProofInputs::application_ky`.
        for poly in &outputs.witnessed_polys {
            poly.com.write(dr, &mut elements)?;
        }
        for query in &outputs.poly_queries {
            query.poly_slot.write(dr, &mut elements)?;
            query.x.write(dr, &mut elements)?;
            query.y.write(dr, &mut elements)?;
        }
        // Then the challenge slots: per slot, every input point's coordinates
        // followed by the challenge. The parent's binding circuit re-derives
        // the challenge from those points.
        for pair in &outputs.challenge_pairs {
            for point in &pair.points {
                point.write(dr, &mut elements)?;
            }
            pair.challenge.write(dr, &mut elements)?;
        }

        // Read every hook's wires back out as values for the fuse.
        let framework = outputs.into_values()?;

        let adapter_aux = D::try_just(|| {
            let left_header = elements[0..HEADER_SIZE]
                .iter()
                .map(|e| *e.value().take())
                .collect_fixed()?;

            let right_header = elements[HEADER_SIZE..HEADER_SIZE * 2]
                .iter()
                .map(|e| *e.value().take())
                .collect_fixed()?;

            Ok(AdapterAux {
                left_header,
                right_header,
                output_data: output_data.take(),
                step_aux: step_aux.take(),
                framework: framework.take(),
            })
        })?;

        Ok(WithAux::new(FixedVec::try_from(elements)?, adapter_aux))
    }
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::ff::Field;
    use ragu_circuits::{Circuit, staging::MultiStage};
    use ragu_core::{
        drivers::emulator::Emulator,
        gadgets::{Bound, Kind},
        maybe::{Always, Maybe, MaybeKind},
    };
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::allocator::{Allocator, Standard};

    use super::*;
    use crate::{
        header::{Header, Suffix},
        step::{Encoded, Index, Step},
    };

    // The per-claim bridge stages sit at the end of the nested stage chain, so
    // building one needs a rank that fits `skip_gates + num_gates` (~177).
    // `TestRank` (n = 32) is too small; production rank is unaffected.
    type TestR = ragu_circuits::polynomials::ProductionRank;
    const HEADER_SIZE: usize = 4;

    struct TestHeader;

    impl Header<Fp> for TestHeader {
        const SUFFIX: Suffix = Suffix::new(50);
        type Data = Fp;
        type Output = Kind![Fp; Element<'_, _>];

        fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
            dr: &mut D,
            allocator: &mut A,
            witness: DriverValue<D, Self::Data>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, allocator, witness)
        }
    }

    struct TestStep;

    impl Step<Pasta> for TestStep {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = TestHeader;
        type Right = TestHeader;
        type Output = TestHeader;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
            &self,
            ctx: &mut StepCtx<'_, 'dr, D, Pasta>,
            _: DriverValue<D, ()>,
            left: DriverValue<D, Fp>,
            right: DriverValue<D, Fp>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )> {
            let dr = &mut *ctx.dr;
            let allocator = &mut Standard::new();
            // Allocate elements for left and right
            let left_elem = Element::alloc(dr, allocator, left)?;
            let right_elem = Element::alloc(dr, allocator, right)?;

            // Output is sum of left and right
            let output_elem = left_elem.add(dr, &right_elem);
            let output_val = output_elem.value().map(|v| *v);

            let left_enc = Encoded::from_gadget(left_elem);
            let right_enc = Encoded::from_gadget(right_elem);
            let output_enc = Encoded::from_gadget(output_elem);

            Ok(((left_enc, right_enc, output_enc), output_val, D::unit()))
        }
    }

    /// Arbitrary blinds for tests that only care about circuit shape.
    fn test_alphas() -> Alphas<Pasta> {
        Alphas {
            bridge: <Pasta as Cycle>::ScalarField::ONE,
        }
    }

    /// Like [`TestStep`], but derives a challenge and folds it into the output.
    ///
    /// The challenge takes no input points: a step's cost does not depend on
    /// how many it passes, and these tests are about the call's circuit
    /// structure, not about what the challenge binds.
    struct ChallengeStep;

    impl Step<Pasta> for ChallengeStep {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = TestHeader;
        type Right = TestHeader;
        type Output = TestHeader;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
            &self,
            ctx: &mut StepCtx<'_, 'dr, D, Pasta>,
            _: DriverValue<D, ()>,
            left: DriverValue<D, Fp>,
            right: DriverValue<D, Fp>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )> {
            let allocator = &mut Standard::new();
            let left_elem = Element::alloc(ctx.dr, allocator, left)?;
            let right_elem = Element::alloc(ctx.dr, allocator, right)?;

            // The outputs are deferred; only the wires are used.
            let challenge = ctx.derive_challenge(&[])?;

            // Output = left + right + challenge, so the deferred challenge
            // wire participates in downstream circuit structure.
            let sum = left_elem.add(ctx.dr, &right_elem);
            let output_elem = sum.add(ctx.dr, &challenge);
            let output_val = output_elem.value().map(|v| *v);

            Ok((
                (
                    Encoded::from_gadget(left_elem),
                    Encoded::from_gadget(right_elem),
                    Encoded::from_gadget(output_elem),
                ),
                output_val,
                D::unit(),
            ))
        }
    }

    #[test]
    fn instance_len_covers_headers_polys_claims_and_challenges() {
        let slots = NUM_POLY_SLOTS * 2
            + NUM_QUERY_SLOTS * 3
            + NUM_CHALLENGE_SLOTS * (CHALLENGE_POINTS_PER_CALL * 2 + 1);
        assert_eq!(InstanceLen::<1>::len(), 3 + slots);
        assert_eq!(InstanceLen::<4>::len(), 12 + slots);
        assert_eq!(InstanceLen::<10>::len(), 30 + slots);
    }

    #[test]
    fn adapter_witness_produces_correct_output_size() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter =
            Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep, Some(Pasta::baked()))
                .expect("adapter construction should succeed");
        let witness = Always::maybe_just(|| (test_alphas(), Fp::from(10u64), Fp::from(20u64), ()));

        let output = MultiStage::new(adapter)
            .witness(dr, witness)
            .expect("witness should succeed")
            .into_output();

        // Output should have 3 * HEADER_SIZE elements (left + right + output headers)
        assert_eq!(
            output.len(),
            HEADER_SIZE * 3
                + NUM_POLY_SLOTS * 2
                + NUM_QUERY_SLOTS * 3
                + NUM_CHALLENGE_SLOTS * (CHALLENGE_POINTS_PER_CALL * 2 + 1)
        );
    }

    #[test]
    fn adapter_witness_extracts_aux_correctly() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter =
            Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep, Some(Pasta::baked()))
                .expect("adapter construction should succeed");
        let witness = Always::maybe_just(|| (test_alphas(), Fp::from(10u64), Fp::from(20u64), ()));

        let aux = MultiStage::new(adapter)
            .witness(dr, witness)
            .expect("witness should succeed")
            .into_aux();

        let AdapterAux {
            left_header,
            right_header,
            output_data,
            step_aux: _,
            framework: _,
        } = aux.take();

        // Left header should start with 10
        assert_eq!(left_header[0], Fp::from(10u64));
        // Right header should start with 20
        assert_eq!(right_header[0], Fp::from(20u64));
        // Step aux should be 10 + 20 = 30
        assert_eq!(output_data, Fp::from(30u64));
    }

    /// A step without `derive_challenge` calls discovers no calls.
    #[test]
    fn discovery_finds_no_calls_for_plain_step() {
        let adapter =
            Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep, Some(Pasta::baked()))
                .expect("discovery should succeed");
        assert_eq!(adapter.challenge_calls(), 0);
    }

    /// The dry run counts each `derive_challenge` call.
    #[test]
    fn discovery_finds_challenge_call() {
        let adapter = Adapter::<Pasta, ChallengeStep, TestR, HEADER_SIZE>::new(
            ChallengeStep,
            Some(Pasta::baked()),
        )
        .expect("discovery should succeed");
        assert_eq!(adapter.challenge_calls(), 1);
    }

    /// A step body that derives more challenges than there are slots is
    /// rejected at registration, when the dry run trips the cap.
    #[test]
    fn discovery_rejects_more_challenges_than_slots() {
        struct TooManyChallenges;

        impl Step<Pasta> for TooManyChallenges {
            const INDEX: Index = Index::new(0);
            type Witness<'source> = ();
            type Aux<'source> = ();
            type Left = TestHeader;
            type Right = TestHeader;
            type Output = TestHeader;

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
                &self,
                ctx: &mut StepCtx<'_, 'dr, D, Pasta>,
                _: DriverValue<D, ()>,
                left: DriverValue<D, Fp>,
                right: DriverValue<D, Fp>,
            ) -> Result<(
                (
                    Encoded<'dr, D, Self::Left, HS>,
                    Encoded<'dr, D, Self::Right, HS>,
                    Encoded<'dr, D, Self::Output, HS>,
                ),
                DriverValue<D, Fp>,
                DriverValue<D, ()>,
            )> {
                let allocator = &mut Standard::new();
                let left_elem = Element::alloc(ctx.dr, allocator, left)?;
                let right_elem = Element::alloc(ctx.dr, allocator, right)?;

                let mut output = left_elem.clone();
                for _ in 0..crate::NUM_CHALLENGE_SLOTS + 1 {
                    let challenge = ctx.derive_challenge(&[])?;
                    output = output.add(ctx.dr, &challenge);
                }

                let output_val = output.value().map(|v| *v);
                Ok((
                    (
                        Encoded::from_gadget(left_elem),
                        Encoded::from_gadget(right_elem),
                        Encoded::from_gadget(output),
                    ),
                    output_val,
                    D::unit(),
                ))
            }
        }

        let error = Adapter::<Pasta, TooManyChallenges, TestR, HEADER_SIZE>::new(
            TooManyChallenges,
            Some(Pasta::baked()),
        )
        .err()
        .expect("the challenge slot cap should reject this step");
        assert!(
            alloc::format!("{error}").contains("challenge slots"),
            "unexpected error: {error}"
        );
    }

    /// The full adapter synthesis (in-circuit challenge derivation + deferred
    /// output allocation) completes on a structure-only driver for a step
    /// that derives a challenge.
    #[test]
    fn adapter_witness_synthesizes_challenge_structure() {
        // A counting driver: no witness values, so the deferred output value
        // closures never run.
        let mut dr: Emulator<Wireless<Empty, Fp>> = Emulator::counter();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, ChallengeStep, TestR, HEADER_SIZE>::new(
            ChallengeStep,
            Some(Pasta::baked()),
        )
        .expect("discovery should succeed");

        let output = MultiStage::new(adapter)
            .witness(dr, Empty)
            .expect("structure-only synthesis should succeed")
            .into_output();

        assert_eq!(
            output.len(),
            HEADER_SIZE * 3
                + NUM_POLY_SLOTS * 2
                + NUM_QUERY_SLOTS * 3
                + NUM_CHALLENGE_SLOTS * (CHALLENGE_POINTS_PER_CALL * 2 + 1)
        );
    }
}
