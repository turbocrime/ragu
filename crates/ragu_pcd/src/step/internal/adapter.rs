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
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Bound, Kind},
    maybe::{Empty, Maybe},
};
use ragu_primitives::{
    Element, GadgetExt,
    allocator::Standard,
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

use super::{
    super::{Step, StepCtx},
    challenge_stage,
};
use crate::{
    Header, NUM_CHALLENGE_SLOTS, NUM_POLY_QUERY_SLOTS,
    framework_hooks::{ClaimWires, FrameworkHookOutputs, FrameworkHooks, PolyQueryClaim},
    internal::challenge::PaddingClaim,
};

/// Length of an application circuit's public instance: the three headers plus
/// the poly-query claim slots (commitment point coordinates and the $(x, y)$
/// opening — four elements per slot).
pub struct InstanceLen<const HEADER_SIZE: usize>;

impl<const HEADER_SIZE: usize> Len for InstanceLen<HEADER_SIZE> {
    fn len() -> usize {
        HEADER_SIZE * 3 + NUM_POLY_QUERY_SLOTS * 4 + NUM_CHALLENGE_SLOTS * 3
    }
}

/// Discovers the hook-call counts of `step` — how many
/// [`derive_challenge`](StepCtx::derive_challenge) calls it makes and how many
/// poly-query claims it raises — by dry-running its witness body once, with an
/// [`Empty`] witness on a counting emulator and the hooks in discovery mode.
///
/// Only counts, never widths: a challenge input's width is a compile-time
/// constant of its type ([`ChallengeInput::ELEMENTS`]), and a claim's wires are
/// a fixed shape.
///
/// This is sound because circuit structure must be witness-independent: the
/// same body runs with `Empty` witnesses for wiring extraction and metrics,
/// so the call sequence cannot differ between this dry run and real
/// synthesis. (A body that violates that requirement is caught at synthesis
/// time by the determinism guard in [`StepCtx::derive_challenge`].)
///
/// [`ChallengeInput::ELEMENTS`]: crate::framework_hooks::ChallengeInput::ELEMENTS
pub(crate) fn discover_hook_layout<C: Cycle, S: Step<C>, const HEADER_SIZE: usize>(
    step: &S,
    poseidon: &C::CircuitPoseidon,
) -> Result<(usize, usize)> {
    let mut dr: Emulator<Wireless<Empty, C::CircuitField>> = Emulator::counter();
    let mut hooks = FrameworkHooks::<_, C::NestedCurve>::new();
    {
        let mut ctx = StepCtx::<'_, '_, _, C>::new(&mut dr, &mut hooks, poseidon);
        step.witness::<_, HEADER_SIZE>(&mut ctx, Empty, Empty, Empty)?;
    }

    let outputs = hooks.into_outputs();
    let num_claims = outputs.poly_query_claims.len();
    if num_claims > NUM_POLY_QUERY_SLOTS {
        return Err(ragu_core::Error::Initialization(
            "step raises more poly-query claims than NUM_POLY_QUERY_SLOTS".into(),
        ));
    }

    Ok((outputs.challenge_calls, num_claims))
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
    /// The step's poly-query claims, padded to exactly
    /// [`NUM_POLY_QUERY_SLOTS`] entries with the canonical padding claim, in
    /// slot order — matching the instance layout the circuit committed to.
    /// Each carries the opened polynomial's coefficients; fuse pre-checks
    /// every claim natively, persists the claim instances in the proof, and
    /// the *next* fuse enforces them recursively via the PCS accumulator.
    pub claims: Vec<PolyQueryClaim<C::CircuitField, C::NestedCurve>>,
    /// The derived-challenge pairs the circuit exposes, padded to exactly
    /// [`NUM_CHALLENGE_SLOTS`] entries, in slot order — matching the instance
    /// layout the circuit committed to.
    pub challenges: Vec<crate::proof::ChallengeOpening<C::NestedCurve, C::CircuitField>>,
    /// The values each challenge stage commits, in slot order, zero-padded to
    /// [`CHALLENGE_WIDTH`](crate::CHALLENGE_WIDTH). Plain field elements: the
    /// fuse holds the rank, so it builds the stage polynomials itself.
    pub challenge_inputs: Vec<[C::CircuitField; crate::CHALLENGE_WIDTH]>,
    // Note: `derive_challenge` calls leave nothing here — the challenge is
    // derived and constrained in-circuit (a Poseidon sponge over the input
    // wires), so nothing needs resolving downstream.
}

pub(crate) struct Adapter<'params, C: Cycle, S, R: Rank, const HEADER_SIZE: usize> {
    step: S,
    /// The number of `derive_challenge` calls the step body makes, discovered
    /// from its witness body at construction time; see
    /// [`discover_hook_layout`]. Part of the circuit structure: each call
    /// synthesizes a sponge over a compile-time-fixed number of wires.
    challenge_calls: usize,
    /// The number of poly-query claims the step body raises, discovered by the
    /// same dry run. Part of the circuit structure: the real synthesis must
    /// raise exactly this many (determinism guard in [`Adapter::witness`]).
    num_claims: usize,
    /// The cycle's baked Poseidon constants, threaded into the step body via
    /// [`StepCtx`] for in-circuit challenge derivation. These are compile-time
    /// constants (`&'static`), so no runtime params are needed to obtain them.
    poseidon: &'static C::CircuitPoseidon,
    /// The canonical padding claim used to fill unused poly-query slots.
    /// `None` on adapters built for registration/keygen (structure-only, where
    /// the value is never taken); `Some` on the proving adapter. The padding is
    /// *witnessed* into each unused slot rather than baked as a circuit
    /// constant, so an application circuit's identity does not depend on the
    /// runtime generators.
    padding: Option<PaddingClaim<C, R>>,
    /// Cycle params and the proof's shared bridge-alpha source, threaded into
    /// [`StepCtx`] so a witnessed polynomial's claim bridge — and therefore its
    /// `com` — can be built. `None` on structure-only adapters.
    claim_bridge: Option<(&'params C::Params, C::ScalarField, C::CircuitField)>,
    _marker: PhantomData<(C, R)>,
}

impl<'params, C: Cycle, S: Step<C>, R: Rank, const HEADER_SIZE: usize>
    Adapter<'params, C, S, R, HEADER_SIZE>
{
    /// Wraps `step` for registration/keygen, discovering its `derive_challenge`
    /// call count and poly-query claim count with a dry run of the witness
    /// body (see [`discover_hook_layout`]). Param-free: discovery uses the baked
    /// Poseidon constants, and the padding claim is left unset (`None`) because
    /// keygen is structure-only and never takes its value. Use
    /// [`proving`](Self::proving) to build the adapter that actually proves.
    pub fn new(step: S) -> Result<Self> {
        let poseidon = C::circuit_poseidon_baked();
        let (challenge_calls, num_claims) =
            discover_hook_layout::<C, S, HEADER_SIZE>(&step, poseidon)?;
        Ok(Adapter {
            step,
            challenge_calls,
            num_claims,
            poseidon,
            padding: None,
            claim_bridge: None,
            _marker: PhantomData,
        })
    }

    /// Wraps `step` for proving. Identical circuit structure to
    /// [`new`](Self::new), but additionally computes the canonical padding
    /// claim from `params` so the unused poly-query slots can be witnessed at
    /// proving time.
    pub fn proving(
        step: S,
        params: &'params C::Params,
        bridge_alpha: C::ScalarField,
        challenge_alpha: C::CircuitField,
    ) -> Result<Self> {
        Ok(Adapter {
            padding: Some(PaddingClaim::new(params)?),
            claim_bridge: Some((params, bridge_alpha, challenge_alpha)),
            ..Self::new(step)?
        })
    }

    /// The number of [`derive_challenge`](StepCtx::derive_challenge) calls the
    /// step body makes.
    #[cfg(test)]
    pub fn challenge_calls(&self) -> usize {
        self.challenge_calls
    }

    /// Fills unused poly-query slots with the canonical padding claim so every
    /// application circuit exposes exactly [`NUM_POLY_QUERY_SLOTS`] claim tuples
    /// in its instance.
    ///
    /// The padding is *witnessed* (like a real claim), not baked as an
    /// in-circuit constant, so an application circuit's structure never depends
    /// on the runtime generators. The value materializes only on value-carrying
    /// (proving) drivers, where `self.padding` is `Some`; structure-only
    /// (keygen) drivers never evaluate these closures (`Empty::try_just`
    /// discards them), so `None` is fine there.
    fn pad_claim_wires<'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        claim_wires: &mut Vec<ClaimWires<'dr, D, C::NestedCurve>>,
    ) -> Result<()> {
        let padding_host = self.padding.as_ref().map(|p| p.host);
        let claim_bridge = self.claim_bridge.map(|(params, alpha, _)| (params, alpha));
        let padding_x = self.padding.as_ref().map(|p| p.x);
        let padding_y = self.padding.as_ref().map(|p| p.y);
        let allocator = &mut Standard::new();
        while claim_wires.len() < NUM_POLY_QUERY_SLOTS {
            // Each slot's `com` is that slot's bridge stage commitment, so the
            // padding commitment differs per slot just like a real claim's.
            let slot = claim_wires.len();
            let com = ragu_primitives::Point::alloc(
                dr,
                D::try_just(move || {
                    let (params, bridge_alpha) = claim_bridge.ok_or_else(|| {
                        ragu_core::Error::InvalidWitness(
                            "padding claim commitment unavailable; a proving adapter must be \
                             built with `Adapter::proving`"
                                .into(),
                        )
                    })?;
                    let host = padding_host.ok_or_else(|| {
                        ragu_core::Error::InvalidWitness("padding claim host unavailable".into())
                    })?;
                    crate::internal::challenge::claim_bridge_commitment::<C, R>(
                        params,
                        slot,
                        crate::internal::challenge::claim_bridge_alpha::<C>(bridge_alpha, slot),
                        host,
                    )
                })?,
            )?;
            let x = Element::alloc(
                dr,
                allocator,
                D::try_just(move || {
                    padding_x.ok_or_else(|| {
                        ragu_core::Error::InvalidWitness("padding claim point unavailable".into())
                    })
                })?,
            )?;
            let y = Element::alloc(
                dr,
                allocator,
                D::try_just(move || {
                    padding_y.ok_or_else(|| {
                        ragu_core::Error::InvalidWitness("padding claim value unavailable".into())
                    })
                })?,
            )?;
            let coefficients =
                D::just(|| alloc::vec![<C::CircuitField as ragu_arithmetic::ff::Field>::ONE]);
            claim_wires.push(ClaimWires {
                com,
                x,
                y,
                coefficients,
            });
        }
        Ok(())
    }

    /// Fills unused challenge slots so every application circuit exposes
    /// exactly [`NUM_CHALLENGE_SLOTS`] pairs in its instance.
    ///
    /// An unused slot still has reserved wires, so it still has a commitment —
    /// the all-zero stage, blinded. Deriving its challenge honestly keeps the
    /// binding circuit uniform: it re-derives every slot without knowing which
    /// the step actually used.
    fn pad_challenge_pairs<'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        pairs: &mut Vec<crate::framework_hooks::ChallengeWires<'dr, D, C::NestedCurve>>,
        inputs: &mut Vec<DriverValue<D, [C::CircuitField; crate::CHALLENGE_WIDTH]>>,
    ) -> Result<()>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        while pairs.len() < NUM_CHALLENGE_SLOTS {
            let slot = pairs.len();
            let claim_bridge = self.claim_bridge;
            let derived = D::try_just(move || {
                let (params, bridge_alpha, challenge_alpha) = claim_bridge.ok_or_else(|| {
                    ragu_core::Error::InvalidWitness(
                        "padding challenge unavailable; a proving adapter must be built with \
                         `Adapter::proving`"
                            .into(),
                    )
                })?;
                crate::internal::challenge::staged_challenge::<C, R>(
                    params,
                    slot,
                    challenge_alpha,
                    bridge_alpha,
                    [<C::CircuitField as ragu_arithmetic::ff::Field>::ZERO; crate::CHALLENGE_WIDTH],
                )
            })?;
            let point =
                ragu_primitives::Point::alloc(dr, derived.as_ref().map(|(point, _)| *point))?;
            let challenge = Element::alloc(dr, allocator, derived.map(|(_, challenge)| challenge))?;
            pairs.push(crate::framework_hooks::ChallengeWires { point, challenge });
            inputs.push(D::just(|| {
                [<C::CircuitField as ragu_arithmetic::ff::Field>::ZERO; crate::CHALLENGE_WIDTH]
            }));
        }
        Ok(())
    }

    /// Extracts the witness-only claim values (instances plus coefficients)
    /// the fuse needs, in slot order, consuming the claim wires.
    fn extract_claims<'dr, D: Driver<'dr, F = C::CircuitField>>(
        claim_wires: Vec<ClaimWires<'dr, D, C::NestedCurve>>,
    ) -> Result<DriverValue<D, Vec<PolyQueryClaim<C::CircuitField, C::NestedCurve>>>> {
        let mut claims_value = D::just(|| Vec::with_capacity(NUM_POLY_QUERY_SLOTS));
        for claim_wire in claim_wires {
            let ClaimWires {
                com,
                x,
                y,
                coefficients,
            } = claim_wire;
            let claim = D::try_just(|| {
                Ok(PolyQueryClaim {
                    com: com.value().take(),
                    x: *x.value().take(),
                    y: *y.value().take(),
                    coefficients: coefficients.take(),
                })
            })?;
            claims_value = claims_value.and_then(|mut v| {
                claim.map(|c| {
                    v.push(c);
                    v
                })
            });
        }
        Ok(claims_value)
    }
}

impl<C: Cycle, S: Step<C> + Send + Sync, R: Rank, const HEADER_SIZE: usize>
    MultiStageCircuit<C::CircuitField, R> for Adapter<'_, C, S, R, HEADER_SIZE>
{
    /// An application circuit's stages are its challenge slots: one committed
    /// partial trace per `derive_challenge` call, so each challenge can be
    /// bound to a commitment of the values known when it was derived.
    type Last = challenge_stage::Last<C::CircuitField, R>;
    type Instance<'source> = (
        FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
        <S::Output as Header<C::CircuitField>>::Data,
    );
    type Witness<'source> = (
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
        // Staging phase 1: reserve every challenge slot's wires before any
        // witness runs. This resolves the whole `Parent` chain up front, which
        // is what lets the slots be handed to the step body one at a time
        // despite having distinct types.
        let (slot0, builder) =
            builder.add_stage::<challenge_stage::Stage0<C::CircuitField, R>>()?;
        let (slot1, builder) =
            builder.add_stage::<challenge_stage::Stage1<C::CircuitField, R>>()?;
        let dr = builder.finish();
        let mut challenge_slots = challenge_stage::Slots::new(slot0, slot1);

        let (left, right, witness) = witness.cast();

        let mut hooks = FrameworkHooks::with_expected(self.challenge_calls);
        let ((left, right, output), output_data, step_aux) = {
            let ctx = match self.claim_bridge {
                Some((params, bridge_alpha, challenge_alpha)) => StepCtx::<'_, '_, _, C>::proving(
                    dr,
                    &mut hooks,
                    self.poseidon,
                    params,
                    bridge_alpha,
                    challenge_alpha,
                ),
                None => StepCtx::<'_, '_, _, C>::new(dr, &mut hooks, self.poseidon),
            };
            let mut ctx = ctx.with_challenge_slots(&mut challenge_slots);
            self.step
                .witness::<_, HEADER_SIZE>(&mut ctx, witness, left, right)?
        };
        let FrameworkHookOutputs {
            poly_query_claims: mut claim_wires,
            challenge_calls,
            mut challenge_pairs,
            mut challenge_inputs,
        } = hooks.into_outputs();

        // Determinism guard, complementing the per-call checks inside
        // `derive_challenge`: every discovered call must have happened, or the
        // synthesized circuit would differ from the registered structure.
        if challenge_calls != self.challenge_calls {
            return Err(ragu_core::Error::InvalidWitness(
                "derive_challenge called fewer times than the discovered call count; \
                 circuit structure must not depend on witness values"
                    .into(),
            ));
        }

        // Determinism guard for poly-query claims: the claim count is part of
        // the circuit structure (each claim's wires occupy an instance slot).
        if claim_wires.len() != self.num_claims {
            return Err(ragu_core::Error::InvalidWitness(
                "enforce_poly_query call count diverged from the discovered claim count; \
                 circuit structure must not depend on witness values"
                    .into(),
            ));
        }

        self.pad_claim_wires(dr, &mut claim_wires)?;
        self.pad_challenge_pairs(dr, &mut challenge_pairs, &mut challenge_inputs)?;

        let mut elements = Vec::with_capacity(InstanceLen::<HEADER_SIZE>::len());
        left.write(dr, &mut elements)?;
        right.write(dr, &mut elements)?;
        output.write(dr, &mut elements)?;
        // The claim slots follow the headers in the instance: per slot, the
        // commitment point's two coordinates, then the opening point and the
        // claimed evaluation. This layout must match
        // `ProofInputs::application_ky`.
        for claim in &claim_wires {
            claim.com.write(dr, &mut elements)?;
            claim.x.write(dr, &mut elements)?;
            claim.y.write(dr, &mut elements)?;
        }
        // Then the challenge slots: per slot, the bridged stage commitment's
        // two coordinates and the challenge hashed from it. The parent's
        // binding circuit re-derives the second from the first.
        for pair in &challenge_pairs {
            pair.point.write(dr, &mut elements)?;
            pair.challenge.write(dr, &mut elements)?;
        }

        // Extract the claim values (instances plus coefficients) for the fuse.
        let claims_value = Self::extract_claims(claim_wires)?;

        let mut inputs_value = D::just(|| Vec::with_capacity(NUM_CHALLENGE_SLOTS));
        for inputs in challenge_inputs {
            inputs_value = inputs_value.and_then(|mut v| {
                inputs.map(|i| {
                    v.push(i);
                    v
                })
            });
        }

        let mut challenges_value = D::just(|| Vec::with_capacity(NUM_CHALLENGE_SLOTS));
        for pair in challenge_pairs {
            let opening = D::try_just(|| {
                Ok(crate::proof::ChallengeOpening {
                    point: pair.point.value().take(),
                    challenge: *pair.challenge.value().take(),
                })
            })?;
            challenges_value = challenges_value.and_then(|mut v| {
                opening.map(|o| {
                    v.push(o);
                    v
                })
            });
        }

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
                claims: claims_value.take(),
                challenges: challenges_value.take(),
                challenge_inputs: inputs_value.take(),
            })
        })?;

        Ok(WithAux::new(FixedVec::try_from(elements)?, adapter_aux))
    }
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::ff::Field;
    use ragu_core::{
        drivers::emulator::Emulator,
        gadgets::{Bound, Kind},
        maybe::{Always, Maybe, MaybeKind},
    };
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::allocator::{Allocator, Standard};

    use ragu_circuits::{Circuit, staging::MultiStage};

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

    /// Like [`TestStep`], but derives a challenge from a two-element gadget,
    /// inducing one stage of width 2.
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

            // Derive a challenge bound to both inputs: induces a stage of
            // width 2. The outputs are deferred; only the wires are used.
            let challenge = ctx.derive_challenge((left_elem.clone(), right_elem.clone()))?;

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
    fn instance_len_covers_headers_claims_and_challenges() {
        let slots = NUM_POLY_QUERY_SLOTS * 4 + NUM_CHALLENGE_SLOTS * 3;
        assert_eq!(InstanceLen::<1>::len(), 3 + slots);
        assert_eq!(InstanceLen::<4>::len(), 12 + slots);
        assert_eq!(InstanceLen::<10>::len(), 30 + slots);
    }

    #[test]
    fn adapter_witness_produces_correct_output_size() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::proving(
            TestStep,
            Pasta::baked(),
            <Pasta as Cycle>::ScalarField::ONE,
            <Pasta as Cycle>::CircuitField::ONE,
        )
        .expect("adapter construction should succeed");
        let witness = Always::maybe_just(|| (Fp::from(10u64), Fp::from(20u64), ()));

        let output = MultiStage::new(adapter)
            .witness(dr, witness)
            .expect("witness should succeed")
            .into_output();

        // Output should have 3 * HEADER_SIZE elements (left + right + output headers)
        assert_eq!(
            output.len(),
            HEADER_SIZE * 3 + NUM_POLY_QUERY_SLOTS * 4 + NUM_CHALLENGE_SLOTS * 3
        );
    }

    #[test]
    fn adapter_witness_extracts_aux_correctly() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::proving(
            TestStep,
            Pasta::baked(),
            <Pasta as Cycle>::ScalarField::ONE,
            <Pasta as Cycle>::CircuitField::ONE,
        )
        .expect("adapter construction should succeed");
        let witness = Always::maybe_just(|| (Fp::from(10u64), Fp::from(20u64), ()));

        let aux = MultiStage::new(adapter)
            .witness(dr, witness)
            .expect("witness should succeed")
            .into_aux();

        let AdapterAux {
            left_header,
            right_header,
            output_data,
            step_aux: _,
            claims: _,
            challenges: _,
            challenge_inputs: _,
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
        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep)
            .expect("discovery should succeed");
        assert_eq!(adapter.challenge_calls(), 0);
    }

    /// The dry run counts each `derive_challenge` call.
    #[test]
    fn discovery_finds_challenge_call() {
        let adapter = Adapter::<Pasta, ChallengeStep, TestR, HEADER_SIZE>::new(ChallengeStep)
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
                    let challenge = ctx.derive_challenge(output.clone())?;
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

        let error = Adapter::<Pasta, TooManyChallenges, TestR, HEADER_SIZE>::new(TooManyChallenges)
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

        let adapter = Adapter::<Pasta, ChallengeStep, TestR, HEADER_SIZE>::new(ChallengeStep)
            .expect("discovery should succeed");

        let output = MultiStage::new(adapter)
            .witness(dr, Empty)
            .expect("structure-only synthesis should succeed")
            .into_output();

        assert_eq!(
            output.len(),
            HEADER_SIZE * 3 + NUM_POLY_QUERY_SLOTS * 4 + NUM_CHALLENGE_SLOTS * 3
        );
    }
}
