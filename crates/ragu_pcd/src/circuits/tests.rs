use super::*;
use crate::*;
use ff::PrimeField;
use native::{
    InternalCircuitIndex,
    stages::{error_m, error_n, eval, preamble, query},
};
use ragu_circuits::staging::{Stage, StageExt};
use ragu_pasta::Pasta;

pub(crate) type R = ragu_circuits::polynomials::R<13>;

// When changing HEADER_SIZE, update the constraint counts by running:
//   cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture
// Then copy-paste the output into the check_constraints! calls in the test below.
pub(crate) const HEADER_SIZE: usize = 65;

// Number of dummy application circuits to register before testing internal
// circuits. This ensures the tests work correctly even when application
// steps are present.
const NUM_APP_STEPS: usize = 6000;

type Preamble = preamble::Stage<Pasta, R, HEADER_SIZE>;
type ErrorN = error_n::Stage<Pasta, R, HEADER_SIZE, NativeParameters>;
type ErrorM = error_m::Stage<Pasta, R, HEADER_SIZE, NativeParameters>;
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

    let circuits = app.native_mesh.circuits();

    macro_rules! check_constraints {
        ($variant:ident, mul = $mul:expr, lin = $lin:expr) => {{
            let idx =
                NUM_APP_STEPS + step::NUM_INTERNAL_STEPS + InternalCircuitIndex::$variant as usize;
            let circuit = &circuits[idx];
            let (actual_mul, actual_lin) = circuit.constraint_counts();
            assert_eq!(
                actual_mul,
                $mul,
                "{}: multiplication constraints: expected {}, got {}",
                stringify!($variant),
                $mul,
                actual_mul
            );
            assert_eq!(
                actual_lin,
                $lin,
                "{}: linear constraints: expected {}, got {}",
                stringify!($variant),
                $lin,
                actual_lin
            );
        }};
    }

    check_constraints!(Hashes1Circuit,         mul = 2045, lin = 3423);
    check_constraints!(Hashes2Circuit,         mul = 1879, lin = 2952);
    check_constraints!(PartialCollapseCircuit, mul = 1756, lin = 1919);
    check_constraints!(FullCollapseCircuit,    mul = 811 , lin = 809);
    check_constraints!(ComputeVCircuit,        mul = 1404, lin = 2280);
}

#[rustfmt::skip]
#[test]
fn test_internal_stage_parameters() {
    macro_rules! check_stage {
        ($Stage:ty, skip = $skip:expr, num = $num:expr) => {{
            assert_eq!(<$Stage>::skip_multiplications(), $skip, "{}: skip", stringify!($Stage));
            assert_eq!(<$Stage as StageExt<_, _>>::num_multiplications(), $num, "{}: num", stringify!($Stage));
        }};
    }

    check_stage!(Preamble, skip =   0, num = 225);
    check_stage!(ErrorN,  skip = 225, num = 186);
    check_stage!(ErrorM,  skip = 411, num = 399);
    check_stage!(Query,   skip = 225, num =  34);
    check_stage!(Eval,    skip = 259, num =  18);
}

/// Helper test to print current constraint counts in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture`
#[test]
fn print_internal_circuit_constraint_counts() {
    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let circuits = app.native_mesh.circuits();

    let variants = [
        ("Hashes1Circuit", InternalCircuitIndex::Hashes1Circuit),
        ("Hashes2Circuit", InternalCircuitIndex::Hashes2Circuit),
        (
            "PartialCollapseCircuit",
            InternalCircuitIndex::PartialCollapseCircuit,
        ),
        (
            "FullCollapseCircuit",
            InternalCircuitIndex::FullCollapseCircuit,
        ),
        ("ComputeVCircuit", InternalCircuitIndex::ComputeVCircuit),
    ];

    println!("\n// Copy-paste the following into test_internal_circuit_constraint_counts:");
    for (name, variant) in variants {
        let idx = NUM_APP_STEPS + step::NUM_INTERNAL_STEPS + variant as usize;
        let circuit = &circuits[idx];
        let (mul, lin) = circuit.constraint_counts();
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
    macro_rules! print_stage {
        ($Stage:ty) => {{
            let skip = <$Stage>::skip_multiplications();
            let num = <$Stage as StageExt<_, _>>::num_multiplications();
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
    print_stage!(ErrorN);
    print_stage!(ErrorM);
    print_stage!(Query);
    print_stage!(Eval);
}

/// Test that the native mesh digest hasn't changed unexpectedly.
///
/// This test verifies that gadget refactorings don't accidentally change the
/// underlying circuit polynomial. If a refactoring produces the same digest,
/// then it's mathematically equivalent.
#[test]
fn test_native_mesh_digest() {
    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let digest = app.native_mesh.get_key();

    let expected: [u8; 32] = [
        0x93, 0xe5, 0xe3, 0xe9, 0x11, 0x96, 0x81, 0x22, 0xaa, 0xba, 0xe1, 0x1e, 0x26, 0x96, 0xcd,
        0xf6, 0x44, 0xd5, 0x9e, 0xe2, 0x39, 0x25, 0x02, 0xdc, 0xdd, 0xa4, 0x8f, 0xad, 0xe2, 0xde,
        0x77, 0x12,
    ];

    assert_eq!(
        digest.to_repr().as_ref(),
        &expected,
        "Mesh digest changed unexpectedly!"
    );
}

/// Test that the nested mesh digest hasn't changed unexpectedly.
///
/// This test verifies that gadget refactorings don't accidentally change the
/// underlying circuit polynomial. If a refactoring produces the same digest,
/// then it's mathematically equivalent.
#[test]
fn test_nested_mesh_digest() {
    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let digest = app.nested_mesh.get_key();

    let expected: [u8; 32] = [
        0x03, 0x34, 0x3d, 0x93, 0x69, 0xa3, 0x95, 0xb5, 0x59, 0x4c, 0xeb, 0x1c, 0x4d, 0x31, 0xa8,
        0x41, 0x64, 0x1b, 0x89, 0x96, 0xa3, 0xa2, 0x21, 0x01, 0x0b, 0x38, 0x31, 0x14, 0xa6, 0xed,
        0x8e, 0x0a,
    ];

    assert_eq!(
        digest.to_repr().as_ref(),
        &expected,
        "Mesh digest changed unexpectedly!"
    );
}
