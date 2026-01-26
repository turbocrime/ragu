use std::hint::black_box;
use std::sync::LazyLock;

use arithmetic::Cycle;
use ff::Field;
use gungraun::{library_benchmark, library_benchmark_group, main};
use ragu_circuits::CircuitExt;
use ragu_circuits::polynomials::{R, structured, unstructured};
use ragu_circuits::registry::{Registry, RegistryBuilder};
use ragu_circuits::test_fixtures::{MySimpleCircuit, SquareCircuit};
use ragu_pasta::{Fp, Pasta};
use rand::rngs::mock::StepRng;

fn mock_rng() -> StepRng {
    StepRng::new(u64::from_le_bytes(*b"didnothn"), 0xF2EE_CAFE_D00D_2DA7)
}

fn setup_structured(
    mut rng: StepRng,
) -> (
    structured::Polynomial<Fp, R<13>>,
    Fp,
    &'static <Pasta as Cycle>::HostGenerators,
) {
    let generators = Pasta::host_generators(Pasta::baked());
    (
        structured::Polynomial::random(&mut rng),
        Fp::random(&mut rng),
        generators,
    )
}

fn setup_unstructured(
    mut rng: StepRng,
) -> (
    unstructured::Polynomial<Fp, R<13>>,
    Fp,
    &'static <Pasta as Cycle>::HostGenerators,
) {
    let generators = Pasta::host_generators(Pasta::baked());
    (
        unstructured::Polynomial::random(&mut rng),
        Fp::random(&mut rng),
        generators,
    )
}

fn setup_revdot(
    mut rng: StepRng,
) -> (
    structured::Polynomial<Fp, R<13>>,
    structured::Polynomial<Fp, R<13>>,
) {
    (
        structured::Polynomial::random(&mut rng),
        structured::Polynomial::random(&mut rng),
    )
}

fn setup_fold(mut rng: StepRng) -> (Vec<structured::Polynomial<Fp, R<13>>>, Fp) {
    let polys: Vec<_> = (0..8)
        .map(|_| structured::Polynomial::<Fp, R<13>>::random(&mut rng))
        .collect();
    (polys, Fp::random(&mut rng))
}

fn setup_eval(mut rng: StepRng) -> (structured::Polynomial<Fp, R<13>>, Fp) {
    (
        structured::Polynomial::random(&mut rng),
        Fp::random(&mut rng),
    )
}

fn setup_dilate(mut rng: StepRng) -> (structured::Polynomial<Fp, R<13>>, Fp) {
    (
        structured::Polynomial::random(&mut rng),
        Fp::random(&mut rng),
    )
}

fn setup_circuit_rx(mut rng: StepRng) -> ((Fp, Fp), Fp) {
    (
        (Fp::random(&mut rng), Fp::random(&mut rng)),
        Fp::random(&mut rng),
    )
}

fn setup_circuit_ky(mut rng: StepRng) -> (Fp, Fp) {
    (Fp::random(&mut rng), Fp::random(&mut rng))
}

fn setup_square_circuit_rx(mut rng: StepRng) -> (Fp, Fp) {
    (Fp::random(&mut rng), Fp::random(&mut rng))
}

fn setup_registry_xy(mut rng: StepRng) -> (Fp, Fp) {
    (Fp::random(&mut rng), Fp::random(&mut rng))
}

fn setup_registry_wxy(mut rng: StepRng) -> (Fp, Fp, Fp) {
    (
        Fp::random(&mut rng),
        Fp::random(&mut rng),
        Fp::random(&mut rng),
    )
}

static BENCH_REGISTRY: LazyLock<Registry<'static, Fp, R<5>>> = LazyLock::new(|| {
    let poseidon = Pasta::circuit_poseidon(Pasta::baked());
    RegistryBuilder::<Fp, R<5>>::new()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .finalize(poseidon)
        .unwrap()
});

#[library_benchmark]
#[bench::structured(args = (mock_rng()), setup = setup_structured)]
fn commit_structured(
    (poly, blind, generators): (
        structured::Polynomial<Fp, R<13>>,
        Fp,
        &'static <Pasta as Cycle>::HostGenerators,
    ),
) {
    black_box(poly.commit(generators, blind));
}

#[library_benchmark]
#[bench::unstructured(args = (mock_rng()), setup = setup_unstructured)]
fn commit_unstructured(
    (poly, blind, generators): (
        unstructured::Polynomial<Fp, R<13>>,
        Fp,
        &'static <Pasta as Cycle>::HostGenerators,
    ),
) {
    black_box(poly.commit(generators, blind));
}

library_benchmark_group!(
    name = poly_commits;
    benchmarks = commit_structured, commit_unstructured
);

#[library_benchmark]
#[bench::revdot(args = (mock_rng()), setup = setup_revdot)]
fn revdot(
    (poly1, poly2): (
        structured::Polynomial<Fp, R<13>>,
        structured::Polynomial<Fp, R<13>>,
    ),
) {
    black_box(poly1.revdot(&poly2));
}

#[library_benchmark]
#[bench::fold(args = (mock_rng()), setup = setup_fold)]
fn fold((polys, scale): (Vec<structured::Polynomial<Fp, R<13>>>, Fp)) {
    black_box(structured::Polynomial::fold(polys.iter(), scale));
}

#[library_benchmark]
#[bench::eval(args = (mock_rng()), setup = setup_eval)]
fn eval((poly, x): (structured::Polynomial<Fp, R<13>>, Fp)) {
    black_box(poly.eval(x));
}

#[library_benchmark]
#[bench::dilate(args = (mock_rng()), setup = setup_dilate)]
fn dilate((mut poly, z): (structured::Polynomial<Fp, R<13>>, Fp)) {
    poly.dilate(z);
    black_box(poly);
}

library_benchmark_group!(
    name = poly_ops;
    benchmarks = revdot, fold, eval, dilate
);

#[library_benchmark]
fn into_object() {
    black_box(CircuitExt::<Fp>::into_object::<R<5>>(MySimpleCircuit).unwrap());
}

#[library_benchmark]
#[bench::rx(args = (mock_rng()), setup = setup_circuit_rx)]
fn rx((witness, key): ((Fp, Fp), Fp)) {
    black_box(MySimpleCircuit.rx::<R<5>>(witness, key).unwrap());
}

#[library_benchmark]
#[bench::ky(args = (mock_rng()), setup = setup_circuit_ky)]
fn ky(instance: (Fp, Fp)) {
    black_box(MySimpleCircuit.ky(instance).unwrap());
}

#[library_benchmark]
fn square_into_object_2() {
    black_box(CircuitExt::<Fp>::into_object::<R<13>>(SquareCircuit { times: 2 }).unwrap());
}

#[library_benchmark]
fn square_into_object_10() {
    black_box(CircuitExt::<Fp>::into_object::<R<13>>(SquareCircuit { times: 10 }).unwrap());
}

#[library_benchmark]
#[bench::rx_2(args = (mock_rng()), setup = setup_square_circuit_rx)]
fn square_rx_2((witness, key): (Fp, Fp)) {
    black_box(
        SquareCircuit { times: 2 }
            .rx::<R<13>>(witness, key)
            .unwrap(),
    );
}

#[library_benchmark]
#[bench::rx_10(args = (mock_rng()), setup = setup_square_circuit_rx)]
fn square_rx_10((witness, key): (Fp, Fp)) {
    black_box(
        SquareCircuit { times: 10 }
            .rx::<R<13>>(witness, key)
            .unwrap(),
    );
}

library_benchmark_group!(
    name = circuit_synthesis;
    benchmarks = into_object, rx, ky, square_into_object_2, square_into_object_10, square_rx_2, square_rx_10
);

#[library_benchmark]
fn finalize() {
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
            .finalize(poseidon)
            .unwrap(),
    );
}

#[library_benchmark]
#[bench::xy(args = (mock_rng()), setup = setup_registry_xy)]
fn xy((x, y): (Fp, Fp)) {
    black_box(BENCH_REGISTRY.xy(x, y));
}

#[library_benchmark]
#[bench::wy(args = (mock_rng()), setup = setup_registry_xy)]
fn wy((w, y): (Fp, Fp)) {
    black_box(BENCH_REGISTRY.wy(w, y));
}

#[library_benchmark]
#[bench::wx(args = (mock_rng()), setup = setup_registry_xy)]
fn wx((w, x): (Fp, Fp)) {
    black_box(BENCH_REGISTRY.wx(w, x));
}

#[library_benchmark]
#[bench::wxy(args = (mock_rng()), setup = setup_registry_wxy)]
fn wxy((w, x, y): (Fp, Fp, Fp)) {
    black_box(BENCH_REGISTRY.wxy(w, x, y));
}

library_benchmark_group!(
    name = registry_ops;
    benchmarks = finalize, xy, wy, wx, wxy
);

main!(
    library_benchmark_groups = poly_commits,
    poly_ops,
    circuit_synthesis,
    registry_ops
);
