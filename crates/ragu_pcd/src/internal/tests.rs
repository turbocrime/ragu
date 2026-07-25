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
// 105 no longer fits: the poly-query claim slots extend application_ky, and
// outer_collapse (the largest internal circuit) was already within a few
// gates of the rank bound at 105.
pub const HEADER_SIZE: usize = 100;

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

    check_constraints!(Hashes1Circuit,          mul = 1458, lin = 2058);
    check_constraints!(Hashes2Circuit,          mul = 2006, lin = 2951);
    check_constraints!(InnerCollapseCircuit,    mul = 1883, lin = 1918);
    check_constraints!(OuterCollapseCircuit,    mul = 2044, lin = 3030);
    check_constraints!(ComputeVCircuit,         mul = 1372, lin = 1979);
    check_constraints!(ChallengeBindingCircuit, mul = 1536, lin = 2379);
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

    check_stage!(Preamble, skip =   1, num = 352);
    check_stage!(OuterError,  skip = 353, num = 186);
    check_stage!(InnerError,  skip = 539, num = 399);
    check_stage!(Query,   skip = 353, num =  29);
    check_stage!(Eval,    skip = 382, num =  25);
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
    // pins them to zero. Only the native digest moves — application circuits
    // are the ones with challenge stages.
    let expected = fp!(0x3417605f0dc3ee69323a6a5cce45b3669a11841965c802df4ef9c8f8a87eb705);

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
    // preamble stashes one more commitment per child.
    let expected = fq!(0x27cc1b6504ed5cebe1e0106265c3cd9527a4b4b5ac5659f1d853649c0a633cae);

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
