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

    check_constraints!(Hashes1Circuit,          mul = 1456, lin = 2038);
    check_constraints!(Hashes2Circuit,          mul = 2004, lin = 2951);
    check_constraints!(InnerCollapseCircuit,    mul = 1881, lin = 1918);
    check_constraints!(OuterCollapseCircuit,    mul = 1998, lin = 2942);
    check_constraints!(ComputeVCircuit,         mul = 1681, lin = 2767);
    check_constraints!(ChallengeBindingCircuit, mul = 1534, lin = 2379);
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
    let expected = fp!(0x0f3b036060e5e3181188837878d16068a29f0bc19b686cdd477d895d2069bd0d);

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
    let expected = fq!(0x074469777e333bb7d9fccb1cb4fd7032dfb174655682398a9acc956e34b4de27);

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

    let padded = crate::framework_hooks::HookLayout::padded();
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

    let padded = crate::framework_hooks::HookLayout::padded();
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
