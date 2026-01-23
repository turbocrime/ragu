mod common;

use arithmetic::Cycle;
use common::{
    mock_rng, setup_circuit_ky, setup_circuit_rx, setup_dilate, setup_eval, setup_fold,
    setup_registry_wxy, setup_registry_xy, setup_revdot, setup_square_circuit_rx,
    setup_structured, setup_unstructured, BENCH_REGISTRY,
};
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use ragu_circuits::CircuitExt;
use ragu_circuits::polynomials::{R, structured};
use ragu_circuits::registry::RegistryBuilder;
use ragu_circuits::test_fixtures::{MySimpleCircuit, SquareCircuit};
use ragu_pasta::{Fp, Pasta};

// ============================================================================
// Poly commits
// ============================================================================

#[library_benchmark]
#[bench::default(args = (mock_rng()), setup = setup_structured)]
fn poly_structured(
    (poly, blind, generators): (
        structured::Polynomial<Fp, R<13>>,
        Fp,
        &'static <Pasta as Cycle>::HostGenerators,
    ),
) {
    black_box(poly.commit(generators, blind));
}

#[library_benchmark]
#[bench::default(args = (mock_rng()), setup = setup_unstructured)]
fn poly_unstructured(
    (poly, blind, generators): (
        ragu_circuits::polynomials::unstructured::Polynomial<Fp, R<13>>,
        Fp,
        &'static <Pasta as Cycle>::HostGenerators,
    ),
) {
    black_box(poly.commit(generators, blind));
}

library_benchmark_group!(
    name = poly_commits;
    benchmarks = poly_structured, poly_unstructured
);

// ============================================================================
// Poly ops
// ============================================================================

#[library_benchmark]
#[bench::default(args = (mock_rng()), setup = setup_revdot)]
fn poly_revdot((poly1, poly2): (structured::Polynomial<Fp, R<13>>, structured::Polynomial<Fp, R<13>>)) {
    black_box(poly1.revdot(&poly2));
}

#[library_benchmark]
#[bench::default(args = (mock_rng()), setup = setup_fold)]
fn poly_fold((polys, scale): (Vec<structured::Polynomial<Fp, R<13>>>, Fp)) {
    black_box(structured::Polynomial::fold(polys.iter(), scale));
}

#[library_benchmark]
#[bench::default(args = (mock_rng()), setup = setup_eval)]
fn poly_eval((poly, x): (structured::Polynomial<Fp, R<13>>, Fp)) {
    black_box(poly.eval(x));
}

#[library_benchmark]
#[bench::default(args = (mock_rng()), setup = setup_dilate)]
fn poly_dilate((mut poly, z): (structured::Polynomial<Fp, R<13>>, Fp)) {
    poly.dilate(z);
    black_box(poly);
}

library_benchmark_group!(
    name = poly_ops;
    benchmarks = poly_revdot, poly_fold, poly_eval, poly_dilate
);

// ============================================================================
// Circuit synthesis
// ============================================================================

#[library_benchmark]
fn circuit_into_object() {
    black_box(CircuitExt::<Fp>::into_object::<R<5>>(MySimpleCircuit));
}

#[library_benchmark]
#[bench::default(args = (mock_rng()), setup = setup_circuit_rx)]
fn circuit_rx((witness, key): ((Fp, Fp), Fp)) {
    black_box(MySimpleCircuit.rx::<R<5>>(witness, key));
}

#[library_benchmark]
#[bench::default(args = (mock_rng()), setup = setup_circuit_ky)]
fn circuit_ky(instance: (Fp, Fp)) {
    black_box(MySimpleCircuit.ky(instance));
}

#[library_benchmark]
fn square_circuit_into_object_2() {
    black_box(CircuitExt::<Fp>::into_object::<R<13>>(SquareCircuit { times: 2 }));
}

#[library_benchmark]
fn square_circuit_into_object_10() {
    black_box(CircuitExt::<Fp>::into_object::<R<13>>(SquareCircuit { times: 10 }));
}

#[library_benchmark]
#[bench::default(args = (mock_rng()), setup = setup_square_circuit_rx)]
fn square_circuit_rx_2((witness, key): (Fp, Fp)) {
    black_box(SquareCircuit { times: 2 }.rx::<R<13>>(witness, key));
}

#[library_benchmark]
#[bench::default(args = (mock_rng()), setup = setup_square_circuit_rx)]
fn square_circuit_rx_10((witness, key): (Fp, Fp)) {
    black_box(SquareCircuit { times: 10 }.rx::<R<13>>(witness, key));
}

library_benchmark_group!(
    name = circuit_synthesis;
    benchmarks = circuit_into_object, circuit_rx, circuit_ky, square_circuit_into_object_2, square_circuit_into_object_10, square_circuit_rx_2, square_circuit_rx_10
);

// ============================================================================
// Registry ops
// ============================================================================

#[library_benchmark]
fn registry_finalize() {
    let poseidon = Pasta::circuit_poseidon(Pasta::baked());
    black_box(
        RegistryBuilder::<Fp, R<25>>::new()
            .register_circuit(SquareCircuit { times: 2 })
            .unwrap()
            .register_circuit(SquareCircuit { times: 5 })
            .unwrap()
            .register_circuit(SquareCircuit { times: 10 })
            .unwrap()
            .register_circuit(SquareCircuit { times: 11 })
            .unwrap()
            .register_circuit(SquareCircuit { times: 19 })
            .unwrap()
            .register_circuit(SquareCircuit { times: 19 })
            .unwrap()
            .register_circuit(SquareCircuit { times: 19 })
            .unwrap()
            .register_circuit(SquareCircuit { times: 19 })
            .unwrap()
            .finalize(poseidon),
    );
}

// Registry evaluation benchmarks use the static BENCH_REGISTRY to measure
// only the evaluation, not the registry construction.

#[library_benchmark]
#[bench::default(args = (mock_rng()), setup = setup_registry_xy)]
fn registry_xy((x, y): (Fp, Fp)) {
    black_box(BENCH_REGISTRY.xy(x, y));
}

#[library_benchmark]
#[bench::default(args = (mock_rng()), setup = setup_registry_xy)]
fn registry_wy((w, y): (Fp, Fp)) {
    black_box(BENCH_REGISTRY.wy(w, y));
}

#[library_benchmark]
#[bench::default(args = (mock_rng()), setup = setup_registry_xy)]
fn registry_wx((w, x): (Fp, Fp)) {
    black_box(BENCH_REGISTRY.wx(w, x));
}

#[library_benchmark]
#[bench::default(args = (mock_rng()), setup = setup_registry_wxy)]
fn registry_wxy((w, x, y): (Fp, Fp, Fp)) {
    black_box(BENCH_REGISTRY.wxy(w, x, y));
}

library_benchmark_group!(
    name = registry_ops;
    benchmarks = registry_finalize, registry_xy, registry_wy, registry_wx, registry_wxy
);

// ============================================================================
// Main
// ============================================================================

main!(
    library_benchmark_groups = poly_commits, poly_ops, circuit_synthesis, registry_ops
);
