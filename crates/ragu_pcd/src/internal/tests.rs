use native::{
    InternalCircuitIndex, InternalCircuitValues, RevdotParameters, RxIndex, RxValues,
    stages::{eval, inner_error, outer_error, preamble, query},
};
use ragu_circuits::staging::{Stage, StageExt};
use ragu_pasta::{Pasta, fp, fq};

use super::*;
use crate::*;
pub type R = ragu_circuits::polynomials::ProductionRank;

use ragu_arithmetic::ff::PrimeField;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    drivers::emulator::{Emulator, Wireless},
    gadgets::{Bound, Gadget},
    maybe::Empty,
};

pub fn assert_stage_values<F, R, S>(stage: &S)
where
    F: PrimeField,
    R: Rank,
    S: Stage<F, R>,
    for<'dr> Bound<'dr, Emulator<Wireless<Empty, F>>, S::OutputKind>:
        Gadget<'dr, Emulator<Wireless<Empty, F>>>,
{
    let mut emulator = Emulator::counter();
    let output = stage
        .witness(&mut emulator, Empty)
        .expect("allocation should succeed");

    assert_eq!(
        output.num_wires().expect("wire counting should succeed"),
        S::values(),
        "Stage::values() does not match actual wire count"
    );
}

// When changing HEADER_SIZE, update the constraint counts by running:
//   cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture
// Then copy-paste the output into the check_constraints! calls in the test below.
//
// This is not a free test parameter. It is the widest header the framework
// claims to support, and it is one half of a pair with
// `NUM_QUERY_SLOTS`: both are charged to `outer_collapse`, the largest
// internal circuit, at roughly 13 gates per header element and 12 per slot.
// Measured points, all against its 2048-gate bound:
//
//     4 slots, header 100 -> 2044   (was the configuration; 4 gates spare)
//     8 slots, header  90 -> 1962   (current)
//     8 slots, header  84 -> 1884
//     8 slots, header  60 -> 1572
//
// So a slot costs about one header element. Ten elements of header bought
// four more claim slots and still left 86 gates spare, where the previous
// configuration had 4. See `NUM_QUERY_SLOTS` for the rest of the trade.
pub const HEADER_SIZE: usize = 90;

// Number of dummy application circuits to register before testing internal
// circuits. This ensures the tests work correctly even when application
// steps are present.
const NUM_APP_STEPS: usize = 6000;

type Preamble = preamble::Stage<Pasta, R, HEADER_SIZE>;
type OuterError = outer_error::Stage<Pasta, R, HEADER_SIZE, RevdotParameters>;
type InnerError = inner_error::Stage<Pasta, R, HEADER_SIZE, RevdotParameters>;
type Query = query::Stage<Pasta, R, HEADER_SIZE>;
type Eval = eval::Stage<Pasta, R, HEADER_SIZE>;

#[rustfmt::skip]
#[test]
fn test_internal_circuit_constraint_counts() {
    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    macro_rules! check_constraints {
        ($variant:ident, mul = $mul:expr, lin = $lin:expr) => {{
            let circuit_index = InternalCircuitIndex::$variant.circuit_index();
            let (actual_gates, actual_constraints) =
                app.native_registry.constraint_counts(circuit_index);
            assert_eq!(
                actual_gates,
                $mul,
                "{}: gates: expected {}, got {}",
                stringify!($variant),
                $mul,
                actual_gates
            );
            assert_eq!(
                actual_constraints,
                $lin,
                "{}: constraints: expected {}, got {}",
                stringify!($variant),
                $lin,
                actual_constraints
            );
        }};
    }

    check_constraints!(Hashes1Circuit,          mul = 1406, lin = 2038);
    check_constraints!(Hashes2Circuit,          mul = 1954, lin = 2951);
    check_constraints!(InnerCollapseCircuit,    mul = 1831, lin = 1918);
    check_constraints!(OuterCollapseCircuit,    mul = 1848, lin = 2742);
    check_constraints!(ComputeVCircuit,         mul = 1226, lin = 1799);
    check_constraints!(ChallengeBindingCircuit, mul = 332, lin = 71);
}

#[rustfmt::skip]
#[test]
fn test_internal_stage_parameters() {
    macro_rules! check_stage {
        ($Stage:ty, skip = $skip:expr, num = $num:expr) => {{
            assert_eq!(<$Stage>::skip_gates(), $skip, "{}: skip", stringify!($Stage));
            assert_eq!(<$Stage as StageExt<_, _>>::num_gates(), $num, "{}: num", stringify!($Stage));
        }};
    }

    check_stage!(Preamble, skip =   1, num = 350);
    check_stage!(OuterError,  skip = 351, num = 186);
    check_stage!(InnerError,  skip = 537, num = 399);
    check_stage!(Query,   skip = 351, num =  25);
    check_stage!(Eval,    skip = 376, num =  27);
}

/// Helper test to print current constraint counts in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture`
#[test]
fn print_internal_circuit_constraint_counts() {
    use alloc::format;
    use std::println;

    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let variants = [
        ("Hashes1Circuit", InternalCircuitIndex::Hashes1Circuit),
        ("Hashes2Circuit", InternalCircuitIndex::Hashes2Circuit),
        (
            "InnerCollapseCircuit",
            InternalCircuitIndex::InnerCollapseCircuit,
        ),
        (
            "OuterCollapseCircuit",
            InternalCircuitIndex::OuterCollapseCircuit,
        ),
        ("ComputeVCircuit", InternalCircuitIndex::ComputeVCircuit),
        (
            "ChallengeBindingCircuit",
            InternalCircuitIndex::ChallengeBindingCircuit,
        ),
    ];

    println!("\n// Copy-paste the following into test_internal_circuit_constraint_counts:");
    for (name, variant) in variants {
        let circuit_index = variant.circuit_index();
        let (mul, lin) = app.native_registry.constraint_counts(circuit_index);
        println!(
            "        check_constraints!({:<24} mul = {:<4}, lin = {});",
            format!("{},", name),
            mul,
            lin
        );
    }
}

/// Helper test to print current stage parameters in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release print_internal_stage -- --nocapture`
#[test]
fn print_internal_stage_parameters() {
    use alloc::format;
    use std::println;

    macro_rules! print_stage {
        ($Stage:ty) => {{
            let skip = <$Stage>::skip_gates();
            let num = <$Stage as StageExt<_, _>>::num_gates();
            println!(
                "        check_stage!({:<8} skip = {:>3}, num = {:>3});",
                format!("{},", stringify!($Stage)),
                skip,
                num
            );
        }};
    }

    println!("\n// Copy-paste the following into test_internal_stage_parameters:");
    print_stage!(Preamble);
    print_stage!(OuterError);
    print_stage!(InnerError);
    print_stage!(Query);
    print_stage!(Eval);
}

/// Verifies the native registry digest matches the expected value.
///
/// This test ensures the wiring polynomial structure is mathematically
/// equivalent to the reference implementation by comparing cryptographic
/// digests.
#[test]
fn test_native_registry_digest() {
    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    // Changed when challenge derivation moved into application-circuit stages:
    // every application circuit gained `NUM_CHALLENGE_SLOTS` staged wire
    // regions and `NUM_CHALLENGE_SLOTS * 3` instance elements (the bridged
    // stage commitment and its challenge, per slot). Changed again when the
    // `challenge_binding` circuit landed: the native registry gained that
    // circuit, a `PreambleFinalStaged` mask, and one more `RxIndex` component
    // (which widens the `query` and `eval` stages by one evaluation per child).
    // Changed again when unused challenge slots started being *filled* rather
    // than skipped: a skipped slot left its `CHALLENGE_WIDTH` reserved wires
    // unconstrained inside a region the stage commits, so each padded slot now
    // pins them to zero. Changed again when slot padding stopped being its own
    // routine and started calling `derive_challenge` — which, like every real
    // call, takes a fresh gate allocator, so a padded slot's challenge element
    // no longer shares a gate with the next slot's. Changed again when the
    // challenge stages became `RxIndex` variants: they moved from their own
    // position in the `_10_p` accumulation into the `RxIndex::ALL` block, and
    // `compute_v` gained the poly-query triple every other rx component has
    // (four more per fuse, one per child per slot). Changed again when
    // `NUM_QUERY_SLOTS` went from 4 to 8 and `HEADER_SIZE` from 100 to 90
    // — both change the width of every application circuit's instance.
    //
    // Changed again when `derive_challenge` became points-only. The challenge
    // stages are gone, so the native registry lost the per-slot stage masks,
    // the per-count final-trace masks, and the `ChallengeStage` rx components
    // — which shrinks `RxIndex::ALL`, and with it every stage that carries one
    // evaluation per rx component. What grew is the instance: a slot now
    // carries `2 * CHALLENGE_POINTS_PER_CALL + 1` elements where it carried
    // three, so the preamble stage and its readers widen by two per slot per
    // child.
    //
    // Changed again — and now **per application** — when the slot capacity
    // became the discovered maximum over the registered steps rather than a
    // framework constant. This digest is *this test application's*: its dummy
    // steps witness no polynomials, raise no claims and derive no challenges,
    // so every slot-dependent width collapses. `challenge_binding` in
    // particular falls from 1534 gates to 332, because an application that
    // never derives a challenge has nothing to bind. Another application's
    // digest will differ, which is the point.
    let expected = fp!(0x2a61c5deef3faeacc2fc54372f7c63ad3e66419338eb5bb673aabf898633a13b);

    assert_eq!(
        app.native_registry.digest(),
        expected,
        "Native registry digest changed unexpectedly!"
    );
}

/// Verifies the nested registry digest matches the expected value.
///
/// This test ensures the wiring polynomial structure is mathematically
/// equivalent to the reference implementation by comparing cryptographic
/// digests.
#[test]
fn test_nested_registry_digest() {
    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    // Changed when the per-claim bridge stages were added: the nested registry
    // gained one bonding mask per poly-query claim slot
    // (`InternalCircuitIndex::BridgeClaim`), and the `Loading` circuit's final
    // stage moved from `eval` to the last claim-bridge stage. Changed again
    // when challenge stages joined the accumulation: the nested preamble
    // stashes two more commitments per child and the endoscaling point list
    // grew by `2 * NUM_CHALLENGE_SLOTS`. Changed again when the challenge
    // bridge stages landed: one more bonding mask per challenge slot, the eval
    // bridge widened to record them, and `Loading`'s final stage moved from the
    // last claim bridge to the last challenge bridge. Changed again when the
    // `challenge_binding` circuit landed: its rx joins the per-child
    // commitment walk, so `NUM_ENDOSCALING_POINTS` grew by two and the nested
    // preamble stashes one more commitment per child. Changed again when the
    // challenge stages became `RxIndex` variants: the point count is unchanged,
    // but they moved within the per-child block, from after the poly-query
    // claims to inside the `RxIndex::ALL` run. Changed again when
    // `NUM_QUERY_SLOTS` went from 4 to 8: four more claim-bridge masks,
    // four more stashed commitments per child, and eight more endoscaling
    // points.
    //
    // Changed again when `derive_challenge` became points-only. A challenge is
    // now hashed from points the step already holds, so nothing about it
    // crosses the curve boundary: the challenge bridge stages and their
    // bonding masks are gone, `Loading`'s final stage moved back from the last
    // challenge bridge to the last claim bridge, the eval and preamble bridges
    // no longer stash challenge-stage commitments, and the endoscaling point
    // list shrank by `2 * NUM_CHALLENGE_SLOTS` per child.
    //
    // Changed again when the slot capacity became per-application: this test
    // application's steps use no slots, so the claim-bridge run is empty, the
    // eval and preamble bridges carry no stashed claims, and the endoscaling
    // point list loses a point per slot per child. See the native digest.
    let expected = fq!(0x3dc08609fc0492d25731f1c7a1c0850349a753c54b3e9b393a7cd9eac58ccf2c);

    assert_eq!(
        app.nested_registry.digest(),
        expected,
        "Nested registry digest changed unexpectedly!"
    );
}

/// Helper test to print current registry digests in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release print_registry_digests -- --nocapture`
#[test]
fn print_registry_digests() {
    use alloc::{format, string::String, vec::Vec};
    use std::println;

    use ragu_arithmetic::ff::PrimeField;

    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let native_digest = app.native_registry.digest();
    let nested_digest = app.nested_registry.digest();

    // Convert to big-endian hex for repr256! format
    let native_bytes: Vec<u8> = native_digest
        .to_repr()
        .as_ref()
        .iter()
        .rev()
        .cloned()
        .collect();
    let nested_bytes: Vec<u8> = nested_digest
        .to_repr()
        .as_ref()
        .iter()
        .rev()
        .cloned()
        .collect();

    println!("\n// Copy-paste the following into the registry digest tests:");
    println!(
        "    let expected = fp!(0x{});",
        native_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!(
        "    let expected = fq!(0x{});",
        nested_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
}

/// The value-level chain layouts describe exactly the geometry the typed
/// `Parent` chains do — every stage's start gate, gate span, and each chain
/// prefix's final-trace start. The masks `register_all` cuts from the layouts
/// are functions of precisely these numbers, so this equality is what keeps
/// them identical to the typed masks they replaced.
#[test]
fn native_chain_layouts_tile_typed_chain() {
    use ragu_circuits::staging::{Stage, StageExt};
    use ragu_pasta::Pasta;

    use crate::internal::native::{RevdotParameters, chain_layouts, stages};

    type Preamble = stages::preamble::Stage<Pasta, R, HEADER_SIZE>;
    type Query = stages::query::Stage<Pasta, R, HEADER_SIZE>;
    type Eval = stages::eval::Stage<Pasta, R, HEADER_SIZE>;
    type Outer = stages::outer_error::Stage<Pasta, R, HEADER_SIZE, RevdotParameters>;
    type Inner = stages::inner_error::Stage<Pasta, R, HEADER_SIZE, RevdotParameters>;
    type F = <Pasta as ragu_arithmetic::Cycle>::CircuitField;

    let padded = crate::framework_hooks::HookLayout::typed_placeholder();
    let (query_chain, error_chain) = chain_layouts::<Pasta, R, HEADER_SIZE>(
        crate::internal::native::InternalCircuitIndex::NUM,
        padded,
        padded,
    );

    for (chain, skips, nums) in [
        (
            &query_chain,
            [
                <Preamble as Stage<F, R>>::skip_gates(),
                <Query as Stage<F, R>>::skip_gates(),
                <Eval as Stage<F, R>>::skip_gates(),
            ],
            [
                <Preamble as StageExt<F, R>>::num_gates(),
                <Query as StageExt<F, R>>::num_gates(),
                <Eval as StageExt<F, R>>::num_gates(),
            ],
        ),
        (
            &error_chain,
            [
                <Preamble as Stage<F, R>>::skip_gates(),
                <Outer as Stage<F, R>>::skip_gates(),
                <Inner as Stage<F, R>>::skip_gates(),
            ],
            [
                <Preamble as StageExt<F, R>>::num_gates(),
                <Outer as StageExt<F, R>>::num_gates(),
                <Inner as StageExt<F, R>>::num_gates(),
            ],
        ),
    ] {
        for (stage, (skip, num)) in skips.iter().zip(nums.iter()).enumerate() {
            assert_eq!(chain.skip_gates(stage), *skip, "stage {stage} start");
            assert_eq!(chain.num_gates(stage), *num, "stage {stage} span");
            assert_eq!(
                chain.skip_gates(stage + 1),
                skip + num,
                "final trace after stage {stage}"
            );
        }
    }
}

/// The nested chain layout describes exactly the geometry the typed `Parent`
/// chain does — same role as `native_chain_layouts_tile_typed_chain`, for the
/// nested side's masks.
#[test]
fn nested_chain_layout_tiles_typed_chain() {
    use ragu_circuits::staging::{Stage, StageExt};
    use ragu_pasta::Pasta;

    use crate::internal::{
        endoscalar::{EndoscalarStage, PointsStage},
        nested::{chain_layout, stages},
    };

    type Host = <Pasta as ragu_arithmetic::Cycle>::HostCurve;
    type F = <Pasta as ragu_arithmetic::Cycle>::ScalarField;

    let padded = crate::framework_hooks::HookLayout::typed_placeholder();
    let chain = chain_layout::<Host, R>(padded, padded, padded);

    let expected: [(usize, usize); 10] = [
        (
            <EndoscalarStage as Stage<F, R>>::skip_gates(),
            <EndoscalarStage as StageExt<F, R>>::num_gates(),
        ),
        (
            <PointsStage<Host> as Stage<F, R>>::skip_gates(),
            <PointsStage<Host> as StageExt<F, R>>::num_gates(),
        ),
        (
            <stages::preamble::Stage<Host, R> as Stage<F, R>>::skip_gates(),
            <stages::preamble::Stage<Host, R> as StageExt<F, R>>::num_gates(),
        ),
        (
            <stages::s_prime::Stage<Host, R> as Stage<F, R>>::skip_gates(),
            <stages::s_prime::Stage<Host, R> as StageExt<F, R>>::num_gates(),
        ),
        (
            <stages::inner_error::Stage<Host, R> as Stage<F, R>>::skip_gates(),
            <stages::inner_error::Stage<Host, R> as StageExt<F, R>>::num_gates(),
        ),
        (
            <stages::outer_error::Stage<Host, R> as Stage<F, R>>::skip_gates(),
            <stages::outer_error::Stage<Host, R> as StageExt<F, R>>::num_gates(),
        ),
        (
            <stages::ab::Stage<Host, R> as Stage<F, R>>::skip_gates(),
            <stages::ab::Stage<Host, R> as StageExt<F, R>>::num_gates(),
        ),
        (
            <stages::query::Stage<Host, R> as Stage<F, R>>::skip_gates(),
            <stages::query::Stage<Host, R> as StageExt<F, R>>::num_gates(),
        ),
        (
            <stages::f::Stage<Host, R> as Stage<F, R>>::skip_gates(),
            <stages::f::Stage<Host, R> as StageExt<F, R>>::num_gates(),
        ),
        (
            <stages::eval::Stage<Host, R> as Stage<F, R>>::skip_gates(),
            <stages::eval::Stage<Host, R> as StageExt<F, R>>::num_gates(),
        ),
    ];

    for (stage, (skip, num)) in expected.iter().enumerate() {
        assert_eq!(chain.skip_gates(stage), *skip, "stage {stage} start");
        assert_eq!(chain.num_gates(stage), *num, "stage {stage} span");
    }
}

#[test]
fn test_internal_circuit_index_all_exhaustive() {
    let mut collected = alloc::vec::Vec::new();
    let _values = InternalCircuitValues::from_fn(|id| {
        collected.push(id);
    });
    assert_eq!(collected.as_slice(), InternalCircuitIndex::ALL);
}

#[test]
fn test_rx_index_all_exhaustive() {
    let mut collected = alloc::vec::Vec::new();
    let _values = RxValues::from_fn(|id| {
        collected.push(id);
    });
    assert_eq!(collected.as_slice(), RxIndex::ALL);
}

/// The branch's acceptance gate: a light application's recursion is
/// **measurably smaller** than a heavy one's.
///
/// Two applications, identical but for what their single step does. The light
/// one witnesses nothing and derives nothing; the heavy one witnesses two
/// polynomials, opens one of them twice, and derives a challenge. Every
/// internal circuit the heavy application registers must be strictly larger,
/// because its capacity is discovered from that step rather than fixed by the
/// framework — which is the whole point of the exercise.
///
/// A framework constant would make these two identical.
mod capacity_is_per_application {
    use ragu_arithmetic::ff::Field;
    use ragu_core::{
        drivers::{Driver, DriverValue},
        gadgets::{Bound, Kind},
        maybe::Maybe,
    };
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::{
        Element,
        allocator::{Allocator, Standard},
    };

    use super::*;
    use crate::{
        header::{Header, Suffix},
        step::{Encoded, Index, Step, StepCtx},
    };

    const HS: usize = 4;

    struct H;

    impl Header<Fp> for H {
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

    /// A step that uses no framework hooks at all.
    struct Light;

    /// A step that witnesses two polynomials, opens one of them twice, and
    /// derives a challenge.
    struct Heavy;

    macro_rules! step {
        ($ty:ty, |$ctx:ident| $hooks:block) => {
            impl Step<Pasta> for $ty {
                const INDEX: Index = Index::new(0);
                type Witness<'source> = ();
                type Aux<'source> = ();
                type Left = H;
                type Right = H;
                type Output = H;

                fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
                    &self,
                    $ctx: &mut StepCtx<'_, 'dr, D, Pasta>,
                    _: DriverValue<D, ()>,
                    left: DriverValue<D, Fp>,
                    right: DriverValue<D, Fp>,
                ) -> Result<(
                    (
                        Encoded<'dr, D, Self::Left, N>,
                        Encoded<'dr, D, Self::Right, N>,
                        Encoded<'dr, D, Self::Output, N>,
                    ),
                    DriverValue<D, Fp>,
                    DriverValue<D, ()>,
                )> {
                    let allocator = &mut Standard::new();
                    let l = Element::alloc($ctx.dr, allocator, left)?;
                    let r = Element::alloc($ctx.dr, allocator, right)?;
                    $hooks
                    let out = l.add($ctx.dr, &r);
                    let out_val = Maybe::map(out.value(), |v| *v);
                    Ok((
                        (
                            Encoded::from_gadget(l),
                            Encoded::from_gadget(r),
                            Encoded::from_gadget(out),
                        ),
                        out_val,
                        D::unit(),
                    ))
                }
            }
        };
    }

    step!(Light, |ctx| {
        let _ = &ctx;
    });

    step!(Heavy, |ctx| {
        // Discovery runs on a structure-only driver, so what matters here is
        // the hook calls, not the values they carry.
        let commitment = D::try_just(|| {
            Err::<crate::poly_commitment::PolyCommitment<Pasta, R>, _>(Error::InvalidWitness(
                "the capacity test never builds a proof".into(),
            ))
        })?;
        let handle = ctx.witness_polynomial::<R>(Maybe::clone(&commitment))?;
        let other = ctx.witness_polynomial::<R>(commitment)?;
        let zero = Element::alloc(ctx.dr, &mut Standard::new(), D::just(|| Fp::ZERO))?;
        // One polynomial opened twice, the other once: three claims over two
        // polynomials, which is the split this branch exists for.
        ctx.enforce_poly_query(&handle, zero.clone(), zero.clone())?;
        ctx.enforce_poly_query(&handle, zero.clone(), zero.clone())?;
        ctx.enforce_poly_query(&other, zero.clone(), zero)?;
        ctx.derive_challenge(&[handle.commitment().clone()])?;
    });

    fn gates(app: &Application<'_, Pasta, R, HS>, id: InternalCircuitIndex) -> usize {
        app.native_registry.constraint_counts(id.circuit_index()).0
    }

    #[test]
    fn a_light_application_pays_less_than_a_heavy_one() {
        let pasta = Pasta::baked();
        let light = ApplicationBuilder::<Pasta, R, HS>::new()
            .register(Light)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        let heavy = ApplicationBuilder::<Pasta, R, HS>::new()
            .register(Heavy)
            .unwrap()
            .finalize(pasta)
            .unwrap();

        // The capacities are what the steps do, discovered, not declared.
        assert_eq!(light.capacity(), framework_hooks::HookLayout::default());
        assert_eq!(heavy.capacity().poly_query.polys, 2);
        assert_eq!(heavy.capacity().poly_query.claims, 3);
        assert_eq!(heavy.capacity().challenge.calls, 1);

        // Every internal circuit that reads a child's slots is strictly
        // smaller in the light application. Under a framework constant these
        // would be equal — that equality is exactly what this branch removed.
        for id in [
            InternalCircuitIndex::Hashes1Circuit,
            InternalCircuitIndex::OuterCollapseCircuit,
            InternalCircuitIndex::ComputeVCircuit,
            InternalCircuitIndex::ChallengeBindingCircuit,
        ] {
            assert!(
                gates(&light, id) < gates(&heavy, id),
                "{id:?}: light {} is not smaller than heavy {}",
                gates(&light, id),
                gates(&heavy, id),
            );
        }

        // And the saving is real, not a rounding difference: a step that
        // derives no challenge pays nothing at all to bind one.
        assert!(
            gates(&light, InternalCircuitIndex::ChallengeBindingCircuit) * 2
                < gates(&heavy, InternalCircuitIndex::ChallengeBindingCircuit),
            "light {} vs heavy {}",
            gates(&light, InternalCircuitIndex::ChallengeBindingCircuit),
            gates(&heavy, InternalCircuitIndex::ChallengeBindingCircuit),
        );
    }
}
