mod common;

use arithmetic::Cycle;
use common::{
    mock_rng, setup_circuit_ky, setup_circuit_rx, setup_dilate, setup_eval, setup_fold,
    setup_registry_wxy, setup_registry_xy, setup_revdot, setup_square_circuit_rx,
    setup_structured, setup_unstructured,
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ragu_circuits::CircuitExt;
use ragu_circuits::polynomials::{R, structured};
use ragu_circuits::registry::RegistryBuilder;
use ragu_circuits::test_fixtures::{MySimpleCircuit, SquareCircuit};
use ragu_pasta::{Fp, Pasta};
use std::hint::black_box;

fn bench_poly_commits(c: &mut Criterion) {
    c.bench_function("circuits/poly_commits/structured", |b| {
        b.iter_batched(
            || setup_structured(mock_rng()),
            |(poly, blind, generators)| {
                black_box(poly.commit(generators, blind));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("circuits/poly_commits/unstructured", |b| {
        b.iter_batched(
            || setup_unstructured(mock_rng()),
            |(poly, blind, generators)| {
                black_box(poly.commit(generators, blind));
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_poly_ops(c: &mut Criterion) {
    c.bench_function("circuits/poly_ops/revdot", |b| {
        b.iter_batched(
            || setup_revdot(mock_rng()),
            |(p1, p2)| {
                black_box(p1.revdot(&p2));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("circuits/poly_ops/fold", |b| {
        b.iter_batched(
            || setup_fold(mock_rng()),
            |(polys, scale)| {
                black_box(structured::Polynomial::fold(polys.iter(), scale));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("circuits/poly_ops/eval", |b| {
        b.iter_batched(
            || setup_eval(mock_rng()),
            |(poly, x)| {
                black_box(poly.eval(x));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("circuits/poly_ops/dilate", |b| {
        b.iter_batched(
            || setup_dilate(mock_rng()),
            |(mut poly, z)| {
                poly.dilate(z);
                black_box(poly);
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_circuit_into_object_fn(c: &mut Criterion) {
    c.bench_function("circuits/synthesis/into_object", |b| {
        b.iter(|| {
            black_box(CircuitExt::<Fp>::into_object::<R<5>>(MySimpleCircuit));
        })
    });
}

fn bench_circuit_rx_fn(c: &mut Criterion) {
    c.bench_function("circuits/witness/rx", |b| {
        b.iter_batched(
            || setup_circuit_rx(mock_rng()),
            |(witness, key)| {
                black_box(MySimpleCircuit.rx::<R<5>>(witness, key));
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_circuit_ky_fn(c: &mut Criterion) {
    c.bench_function("circuits/instance/ky", |b| {
        b.iter_batched(
            || setup_circuit_ky(mock_rng()),
            |instance| {
                black_box(MySimpleCircuit.ky(instance));
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_square_circuit_into_object_fn(c: &mut Criterion) {
    c.bench_function("circuits/synthesis/square_into_object_times_2", |b| {
        b.iter(|| {
            black_box(CircuitExt::<Fp>::into_object::<R<13>>(SquareCircuit { times: 2 }));
        })
    });
    c.bench_function("circuits/synthesis/square_into_object_times_10", |b| {
        b.iter(|| {
            black_box(CircuitExt::<Fp>::into_object::<R<13>>(SquareCircuit { times: 10 }));
        })
    });
}

fn bench_square_circuit_rx_fn(c: &mut Criterion) {
    c.bench_function("circuits/witness/square_rx_times_2", |b| {
        b.iter_batched(
            || setup_square_circuit_rx(mock_rng()),
            |(witness, key)| {
                black_box(SquareCircuit { times: 2 }.rx::<R<13>>(witness, key));
            },
            BatchSize::SmallInput,
        )
    });
    c.bench_function("circuits/witness/square_rx_times_10", |b| {
        b.iter_batched(
            || setup_square_circuit_rx(mock_rng()),
            |(witness, key)| {
                black_box(SquareCircuit { times: 10 }.rx::<R<13>>(witness, key));
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_registry_finalize_fn(c: &mut Criterion) {
    let poseidon = Pasta::circuit_poseidon(Pasta::baked());
    c.bench_function("circuits/registry/finalize_8_square_circuits", |b| {
        b.iter(|| {
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
        })
    });
}

fn bench_registry_evaluations_fn(c: &mut Criterion) {
    let poseidon = Pasta::circuit_poseidon(Pasta::baked());
    let registry = RegistryBuilder::<Fp, R<5>>::new()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .register_circuit(MySimpleCircuit)
        .unwrap()
        .finalize(poseidon)
        .unwrap();

    c.bench_function("circuits/registry/xy", |b| {
        b.iter_batched(
            || setup_registry_xy(mock_rng()),
            |(x, y)| {
                black_box(registry.xy(x, y));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("circuits/registry/wy", |b| {
        b.iter_batched(
            || setup_registry_xy(mock_rng()),
            |(w, y)| {
                black_box(registry.wy(w, y));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("circuits/registry/wx", |b| {
        b.iter_batched(
            || setup_registry_xy(mock_rng()),
            |(w, x)| {
                black_box(registry.wx(w, x));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("circuits/registry/wxy", |b| {
        b.iter_batched(
            || setup_registry_wxy(mock_rng()),
            |(w, x, y)| {
                black_box(registry.wxy(w, x, y));
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group! {
    name = poly_commits;
    config = Criterion::default();
    targets = bench_poly_commits
}

criterion_group! {
    name = poly_ops;
    config = Criterion::default();
    targets = bench_poly_ops
}

criterion_group! {
    name = circuit_synthesis;
    config = Criterion::default();
    targets =
        bench_circuit_into_object_fn,
        bench_circuit_rx_fn,
        bench_circuit_ky_fn,
        bench_square_circuit_into_object_fn,
        bench_square_circuit_rx_fn
}

criterion_group! {
    name = registry_ops;
    config = Criterion::default();
    targets =
        bench_registry_finalize_fn,
        bench_registry_evaluations_fn
}

criterion_main!(poly_commits, poly_ops, circuit_synthesis, registry_ops);
