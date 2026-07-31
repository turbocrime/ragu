use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, GadgetExt,
    vec::{CollectFixed, ConstLen, FixedVec},
};

use super::super::{Step, StepCtx};
use crate::{
    Header,
    framework_hooks::{FrameworkAux, FrameworkHooks, HookLayout, ProofValues},
};

/// Length of an application circuit's public instance: the three headers, then
/// the polynomial slots (commitment point coordinates — two elements per slot),
/// then the query slots (the opened polynomial's commitment and the $(x, y)$
/// opening — four elements per slot), then the challenge slots (the coordinates
/// of every input point, then the challenge).
///
/// A query carries the commitment of the polynomial it opens — the same
/// allocated [`Point`](ragu_primitives::Point), written at two instance
/// positions, so no constraint is spent making them agree. A repeat opening
/// costs a query slot and no polynomial slot.
pub fn instance_len(header_size: usize, capacity: HookLayout) -> usize {
    header_size * 3
        + capacity.poly_query.polys * 2
        + capacity.poly_query.claims * 4
        + capacity.challenge.calls * (capacity.challenge.width * 2 + 1)
        + capacity.poly_query.polys * 4
}

/// [`instance_len`] as a [`Len`](ragu_primitives::vec::Len), so the application
/// circuit's instance can be a `FixedVec`.
///
/// It is a computed length, not one of the declared consts, so it cannot ride
/// as a const-generic argument on stable — hence a type that computes it. The
/// arithmetic is not restated here: this calls [`instance_len`] on the capacity
/// its own const parameters declare, so the `FixedVec`'s length and the number
/// of elements the adapter writes are one statement.
pub struct InstanceLen<
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
>;

impl<
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
> ragu_primitives::vec::Len
    for InstanceLen<HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>
{
    fn len() -> usize {
        instance_len(
            HEADER_SIZE,
            HookLayout::declared(POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH),
        )
    }
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

pub(crate) struct Adapter<
    'params,
    C: Cycle,
    S,
    R: Rank,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
> {
    step: S,
    /// The cycle's runtime parameters, absent during registration.
    ///
    /// `ApplicationBuilder::register` runs before
    /// [`finalize`](crate::ApplicationBuilder::finalize) supplies them, and it
    /// only needs the circuit's *structure*; the parameters are read solely to
    /// build a proof's witness values. So registration passes `None`, and the
    /// one place that reads them — [`witness`](MultiStageCircuit::witness) —
    /// does so inside a `try_just` that a structure-only driver discards.
    params: Option<&'params C::Params>,
    _marker: PhantomData<(C, R)>,
}

impl<
    'params,
    C: Cycle,
    S: Step<C>,
    R: Rank,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
> Adapter<'params, C, S, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>
{
    /// The application's declared slot capacities — what this circuit's
    /// instance exposes and what [`StepCtx::finish_slots`] pads to. Read off
    /// this type's own const parameters, so it agrees with the shape the type
    /// states; see the crate docs for why capacity is declared.
    pub(crate) const CAPACITY: HookLayout =
        HookLayout::declared(POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH);

    /// Wraps `step` for registration/keygen at [`CAPACITY`](Self::CAPACITY) —
    /// the only constructor, and it takes no capacity: the counts are this
    /// type's const parameters. A step that asks for more slots is rejected
    /// by the hooks at the call that exceeds the capacity.
    ///
    /// `params` is `None` at registration, which runs before the cycle
    /// parameters exist and needs only the circuit's structure; see the
    /// field's documentation.
    pub fn new(step: S, params: Option<&'params C::Params>) -> Self {
        Adapter {
            step,
            params,
            _marker: PhantomData,
        }
    }
}

impl<
    C: Cycle,
    S: Step<C> + Send + Sync,
    R: Rank,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
> MultiStageCircuit<C::CircuitField, R>
    for Adapter<'_, C, S, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>
{
    /// An application circuit has no stages: a challenge input is a point,
    /// already a commitment, so there is nothing to compress into a committed
    /// partial trace and nothing to stage.
    type Last = ();
    type Instance<'source> = (
        FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        <S::Output as Header<C::CircuitField>>::Data,
    );
    type Witness<'source> = (
        // The proof's bridge blind source. Absent during registration, because
        // it does not exist until a *proof* is being built — which is why it
        // rides a `DriverValue` while the cycle parameters, absent for a
        // different reason, are an `Option` field on the adapter instead.
        C::ScalarField,
        <S::Left as Header<C::CircuitField>>::Data,
        <S::Right as Header<C::CircuitField>>::Data,
        S::Witness<'source>,
    );
    type Output = Kind![
        C::CircuitField;
        ragu_primitives::vec::FixedVec<
            Element<'_, _>,
            InstanceLen<HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>,
        >
    ];
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

        let (bridge_alpha, left, right, witness) = witness.cast();
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
            Ok(ProofValues::new(params, bridge_alpha.take()))
        })?;

        let mut hooks = FrameworkHooks::new(Self::CAPACITY, Maybe::clone(&proof_values));
        let ((left, right, output), output_data, step_aux) = {
            let mut ctx = StepCtx::<'_, '_, _, C>::new(dr, &mut hooks);
            let body = self
                .step
                .witness::<_, HEADER_SIZE>(&mut ctx, witness, left, right)?;
            // Fill whatever slots the body left over, through the same hooks it
            // used. Each hook already rejected a call past the declared
            // capacity, so there is no total to reconcile here.
            ctx.finish_slots::<R>()?;
            body
        };
        // Every slot's lift instance wires must exist; slots the body opened
        // through `poly_limbs` already have theirs (derived from constrained
        // bits), the rest get plain value-filled wires here.
        hooks.fill_missing_lifts(dr)?;
        let outputs = hooks.into_outputs();

        let mut elements = Vec::with_capacity(instance_len(HEADER_SIZE, Self::CAPACITY));
        left.write(dr, &mut elements)?;
        right.write(dr, &mut elements)?;
        output.write(dr, &mut elements)?;
        // The polynomial slots follow the headers: per slot, the commitment
        // point's two coordinates. Then the query slots: per slot, the opened
        // polynomial's commitment, the opening point, and the claimed
        // evaluation. This layout must match `ProofInputs::application_ky`.
        //
        // A query's `bridge_com` is the very `Point` its polynomial's slot wrote —
        // `enforce_polynomial_query` reads it out of `witnessed_polys` rather
        // than taking it from the caller — so this writes one wire at two
        // positions and the parent inherits their equality through the revdot
        // identity, with nothing to enforce.
        for poly in &outputs.witnessed_polys {
            poly.bridge_com.write(dr, &mut elements)?;
        }
        for query in &outputs.poly_queries {
            query.bridge_com.write(dr, &mut elements)?;
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
        // Last, the lift region: per polynomial slot, the four `lift(l_k)`
        // wires for the host commitment's limbs. Appended after the existing
        // regions so their offsets (and the value reads below) are unmoved.
        for poly in &outputs.witnessed_polys {
            for lift in poly.lifts.as_ref().ok_or_else(|| {
                ragu_core::Error::InvalidWitness(
                    "fill_missing_lifts runs before the instance is written".into(),
                )
            })? {
                lift.write(dr, &mut elements)?;
            }
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

        Ok(WithAux::new(
            ragu_primitives::vec::FixedVec::try_from(elements)?,
            adapter_aux,
        ))
    }
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::ff::Field;
    use ragu_circuits::{Circuit, staging::MultiStage};
    use ragu_core::{
        drivers::emulator::{Emulator, Wireless},
        gadgets::{Bound, Kind},
        maybe::{Always, Empty, Maybe, MaybeKind},
    };
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::allocator::{Allocator, Standard};

    use super::*;
    use crate::{
        framework_hooks::{ChallengeLayout, PolyQueryLayout},
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

    /// An arbitrary bridge blind for tests that only care about circuit shape.
    fn test_bridge_alpha() -> <Pasta as Cycle>::ScalarField {
        <Pasta as Cycle>::ScalarField::ONE
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

    /// The instance is three headers plus the application's slots, and every
    /// term scales with the capacity it is drawn from.
    #[test]
    fn instance_len_covers_headers_polys_claims_and_challenges() {
        let capacity = HookLayout {
            challenge: ChallengeLayout { calls: 2, width: 2 },
            poly_query: PolyQueryLayout {
                polys: 8,
                claims: 8,
            },
        };
        // Two elements per polynomial (its commitment), four per claim (the
        // opened polynomial's commitment, then the `(x, y)` opening), and four
        // more per polynomial in the trailing lift region.
        let slots = 8 * 2 + 8 * 4 + 2 * (capacity.challenge.width * 2 + 1) + 8 * 4;
        assert_eq!(instance_len(1, capacity), 3 + slots);
        assert_eq!(instance_len(4, capacity), 12 + slots);
        assert_eq!(instance_len(10, capacity), 30 + slots);

        // Half the polynomial slots, half their contribution — two commitment
        // wires and four lift wires each.
        let smaller = HookLayout {
            poly_query: PolyQueryLayout {
                polys: 4,
                ..capacity.poly_query
            },
            ..capacity
        };
        assert_eq!(instance_len(4, smaller), instance_len(4, capacity) - 24);
    }

    #[test]
    fn adapter_witness_produces_correct_output_size() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        type Subject = Adapter<'static, Pasta, TestStep, TestR, HEADER_SIZE, 0, 0, 0, 2>;
        let adapter = Subject::new(TestStep, Some(Pasta::baked()));
        let witness =
            Always::maybe_just(|| (test_bridge_alpha(), Fp::from(10u64), Fp::from(20u64), ()));

        let output = MultiStage::new(adapter)
            .witness(dr, witness)
            .expect("witness should succeed")
            .into_output();

        // Output should have 3 * HEADER_SIZE elements (left + right + output headers)
        assert_eq!(output.len(), instance_len(HEADER_SIZE, Subject::CAPACITY));
    }

    #[test]
    fn adapter_witness_extracts_aux_correctly() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE, 0, 0, 0, 2>::new(
            TestStep,
            Some(Pasta::baked()),
        );
        let witness =
            Always::maybe_just(|| (test_bridge_alpha(), Fp::from(10u64), Fp::from(20u64), ()));

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

    /// A step body that derives more challenges than the application declared
    /// is rejected by the hook, at the call that exceeds the capacity.
    #[test]
    fn a_step_that_exceeds_the_declared_capacity_is_rejected() {
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
                for _ in 0..3 {
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

        // The step derives three challenges; the application declared two.
        let adapter = Adapter::<Pasta, TooManyChallenges, TestR, HEADER_SIZE, 0, 0, 2, 2>::new(
            TooManyChallenges,
            Some(Pasta::baked()),
        );

        let mut dr: Emulator<Wireless<Empty, Fp>> = Emulator::counter();
        let error = MultiStage::new(adapter)
            .witness(&mut dr, Empty)
            .err()
            .expect("a step that derives past the declared capacity should be rejected");
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

        type Subject = Adapter<'static, Pasta, ChallengeStep, TestR, HEADER_SIZE, 0, 0, 1, 2>;
        let adapter = Subject::new(ChallengeStep, Some(Pasta::baked()));

        let output = MultiStage::new(adapter)
            .witness(dr, Empty)
            .expect("structure-only synthesis should succeed")
            .into_output();

        assert_eq!(output.len(), instance_len(HEADER_SIZE, Subject::CAPACITY));
    }
}
