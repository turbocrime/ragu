use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_arithmetic::{Coeff, Cycle};
use ragu_circuits::{Circuit, WithAux, polynomials::Rank, staging::InducedStages};
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
    allocator::{Allocator, Standard},
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

use super::super::{Step, StepCtx};
use crate::{
    Header, NUM_POLY_QUERY_SLOTS,
    framework_hooks::{ClaimWires, FrameworkHookOutputs, FrameworkHooks, PolyQueryClaim},
    internal::challenge::PaddingClaim,
};

/// Length of an application circuit's public instance: the three headers plus
/// the poly-query claim slots (commitment point coordinates and the $(x, y)$
/// opening — four elements per slot).
pub struct InstanceLen<const HEADER_SIZE: usize>;

impl<const HEADER_SIZE: usize> Len for InstanceLen<HEADER_SIZE> {
    fn len() -> usize {
        HEADER_SIZE * 3 + NUM_POLY_QUERY_SLOTS * 4
    }
}

/// Discovers the induced stage layout of `step` by dry-running its witness
/// body once, with an [`Empty`] witness on a counting emulator and the hooks
/// in discovery mode.
///
/// Each [`derive_challenge`](StepCtx::derive_challenge) call records its
/// gadget's wire width; the widths in call order *are* the layout. This is
/// sound because circuit structure must be witness-independent: the same body
/// runs with `Empty` witnesses for wiring extraction and metrics, so the call
/// sequence cannot differ between this dry run and real synthesis. (A body
/// that violates that requirement is caught at synthesis time by the
/// determinism guard in
/// [`FrameworkHooks::derive_challenge`].)
pub(crate) fn discover_induced_stages<C: Cycle, S: Step<C>, const HEADER_SIZE: usize>(
    step: &S,
    poseidon: &C::CircuitPoseidon,
) -> Result<(InducedStages, usize)> {
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

    Ok((
        InducedStages::new(
            outputs
                .derived_challenges
                .iter()
                .map(|stage| stage.num_wires)
                .collect(),
        ),
        num_claims,
    ))
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
    // Note: the stages induced by `derive_challenge` do not travel here — the
    // challenge is derived and constrained in-circuit, so nothing needs
    // resolving downstream. The stage geometry is deterministic
    // ([`Adapter::induced_stages`]) and is what the future succinct-challenge
    // optimization will use to carve each stage's slice out of the trace
    // positionally.
}

pub(crate) struct Adapter<'params, C: Cycle, S, R: Rank, const HEADER_SIZE: usize> {
    step: S,
    /// The induced stage layout discovered from the step's witness body at
    /// construction time; see [`discover_induced_stages`].
    induced: InducedStages,
    /// The number of poly-query claims the step body raises, discovered by the
    /// same dry run. Part of the circuit structure: the real synthesis must
    /// raise exactly this many (determinism guard in [`Adapter::witness`]).
    num_claims: usize,
    /// The cycle's Poseidon parameters, threaded into the step body via
    /// [`StepCtx`] (sound in-circuit challenge derivation needs them on every
    /// driver, including the structure-only registration passes).
    poseidon: &'params C::CircuitPoseidon,
    /// The canonical padding claim filling unused poly-query instance slots.
    padding: PaddingClaim<C, R>,
    _marker: PhantomData<(C, R)>,
}

impl<'params, C: Cycle, S: Step<C>, R: Rank, const HEADER_SIZE: usize>
    Adapter<'params, C, S, R, HEADER_SIZE>
{
    /// Wraps `step`, discovering its induced stage layout and poly-query claim
    /// count with a dry run of the witness body (see
    /// [`discover_induced_stages`]).
    pub fn new(step: S, params: &'params C::Params) -> Result<Self> {
        let poseidon = C::circuit_poseidon(params);
        let (induced, num_claims) = discover_induced_stages::<C, S, HEADER_SIZE>(&step, poseidon)?;
        Ok(Adapter {
            step,
            induced,
            num_claims,
            poseidon,
            padding: PaddingClaim::new(params)?,
            _marker: PhantomData,
        })
    }

    /// The stage layout induced by the step's
    /// [`derive_challenge`](StepCtx::derive_challenge) calls.
    pub fn induced_stages(&self) -> &InducedStages {
        &self.induced
    }
}

impl<C: Cycle, S: Step<C>, R: Rank, const HEADER_SIZE: usize> Circuit<C::CircuitField>
    for Adapter<'_, C, S, R, HEADER_SIZE>
{
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

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (left, right, witness) = witness.cast();

        // Reserve the induced stage regions at the head of the trace (gates
        // 1.. — the SYSTEM gate is allocated by orchestration) so their
        // geometry depends only on the discovered widths, mirroring
        // `StageBuilder::configure_stage`. The final trace is zero here; each
        // stage polynomial carries the actual values.
        let mut reserved = Vec::with_capacity(self.induced.len());
        {
            let allocator = &mut Standard::new();
            for stage in 0..self.induced.len() {
                let width = self.induced.width(stage);
                let mut wires = Vec::with_capacity(width);
                for _ in 0..width {
                    wires.push(allocator.alloc(dr, || Ok(Coeff::Zero))?);
                }
                // Pad to a whole number of gates so consecutive stages tile
                // disjoint gate ranges.
                for _ in width..(2 * self.induced.num_gates(stage)) {
                    allocator.alloc(dr, || Ok(Coeff::Zero))?;
                }
                reserved.push(wires);
            }
        }

        let mut hooks = FrameworkHooks::with_reserved(reserved);
        let ((left, right, output), output_data, step_aux) = {
            let mut ctx = StepCtx::<'_, '_, _, C>::new(dr, &mut hooks, self.poseidon);
            self.step
                .witness::<_, HEADER_SIZE>(&mut ctx, witness, left, right)?
        };
        let FrameworkHookOutputs {
            poly_query_claims: mut claim_wires,
            derived_challenges,
        } = hooks.into_outputs();

        // Determinism guard, complementing the per-call checks inside
        // `derive_challenge`: every reserved region must have been consumed,
        // or a stage polynomial would commit to a slice nothing was bound to.
        if derived_challenges.len() != self.induced.len() {
            return Err(ragu_core::Error::InvalidWitness(
                "derive_challenge called fewer times than the discovered stage layout; \
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

        // Fill the remaining slots with the canonical padding claim, as
        // in-circuit constants: every application circuit exposes exactly
        // NUM_POLY_QUERY_SLOTS claim tuples in its instance.
        while claim_wires.len() < NUM_POLY_QUERY_SLOTS {
            let com = ragu_primitives::Point::constant(dr, self.padding.com)?;
            let x = Element::constant(dr, self.padding.x);
            let y = Element::constant(dr, self.padding.y);
            let coefficients =
                D::just(|| alloc::vec![<C::CircuitField as ragu_arithmetic::ff::Field>::ONE]);
            claim_wires.push(ClaimWires {
                com,
                x,
                y,
                coefficients,
            });
        }

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

        // Extract the claim values (instances plus coefficients) for the fuse.
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
            })
        })?;

        Ok(WithAux::new(FixedVec::try_from(elements)?, adapter_aux))
    }
}

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::TestRank;
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

    type TestR = TestRank;
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
    fn instance_len_covers_headers_and_claim_slots() {
        assert_eq!(InstanceLen::<1>::len(), 3 + NUM_POLY_QUERY_SLOTS * 4);
        assert_eq!(InstanceLen::<4>::len(), 12 + NUM_POLY_QUERY_SLOTS * 4);
        assert_eq!(InstanceLen::<10>::len(), 30 + NUM_POLY_QUERY_SLOTS * 4);
    }

    #[test]
    fn adapter_witness_produces_correct_output_size() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep, Pasta::baked())
            .expect("discovery should succeed");
        let witness = Always::maybe_just(|| (Fp::from(10u64), Fp::from(20u64), ()));

        let output = adapter
            .witness(dr, witness)
            .expect("witness should succeed")
            .into_output();

        // Output should have 3 * HEADER_SIZE elements (left + right + output headers)
        assert_eq!(output.len(), HEADER_SIZE * 3 + NUM_POLY_QUERY_SLOTS * 4);
    }

    #[test]
    fn adapter_witness_extracts_aux_correctly() {
        let mut dr = Emulator::execute();
        let dr = &mut dr;

        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep, Pasta::baked())
            .expect("discovery should succeed");
        let witness = Always::maybe_just(|| (Fp::from(10u64), Fp::from(20u64), ()));

        let aux = adapter
            .witness(dr, witness)
            .expect("witness should succeed")
            .into_aux();

        let AdapterAux {
            left_header,
            right_header,
            output_data,
            step_aux: _,
            claims: _,
        } = aux.take();

        // Left header should start with 10
        assert_eq!(left_header[0], Fp::from(10u64));
        // Right header should start with 20
        assert_eq!(right_header[0], Fp::from(20u64));
        // Step aux should be 10 + 20 = 30
        assert_eq!(output_data, Fp::from(30u64));
    }

    /// A step without `derive_challenge` calls discovers an empty layout.
    #[test]
    fn discovery_finds_no_stages_for_plain_step() {
        let adapter = Adapter::<Pasta, TestStep, TestR, HEADER_SIZE>::new(TestStep, Pasta::baked())
            .expect("discovery should succeed");
        assert!(adapter.induced_stages().is_empty());
    }

    /// Each `derive_challenge` call induces one stage whose width is the
    /// gadget's wire count.
    #[test]
    fn discovery_finds_induced_stage() {
        let adapter =
            Adapter::<Pasta, ChallengeStep, TestR, HEADER_SIZE>::new(ChallengeStep, Pasta::baked())
                .expect("discovery should succeed");
        let induced = adapter.induced_stages();
        assert_eq!(induced.len(), 1);
        // Two `Element`s -> width 2, one gate right after the SYSTEM gate.
        assert_eq!(induced.width(0), 2);
        assert_eq!(induced.skip_gates(0), 1);
        assert_eq!(induced.num_gates(0), 1);
        assert_eq!(induced.final_skip_gates(), 2);
    }

    /// The full adapter synthesis (reservation + binding + deferred output
    /// allocation) completes on a structure-only driver for a step that
    /// derives a challenge.
    #[test]
    fn adapter_witness_synthesizes_induced_stage_structure() {
        // A counting driver: no witness values, so the deferred output value
        // closures never run.
        let mut dr: Emulator<Wireless<Empty, Fp>> = Emulator::counter();
        let dr = &mut dr;

        let adapter =
            Adapter::<Pasta, ChallengeStep, TestR, HEADER_SIZE>::new(ChallengeStep, Pasta::baked())
                .expect("discovery should succeed");

        let output = adapter
            .witness(dr, Empty)
            .expect("structure-only synthesis should succeed")
            .into_output();

        assert_eq!(output.len(), HEADER_SIZE * 3 + NUM_POLY_QUERY_SLOTS * 4);
    }
}
