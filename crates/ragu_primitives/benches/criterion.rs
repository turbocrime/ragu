mod common;

use common::{
    BenchEmulator, mock_rng, setup_bool_256, setup_element_fold_8, setup_element_invert,
    setup_element_is_zero, setup_element_mul, setup_element_multiadd_8, setup_extract,
    setup_field_scale, setup_group_scale, setup_point_pair, setup_point_single, setup_sponge,
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ragu_core::maybe::Maybe;
use ragu_primitives::poseidon::Sponge;
use ragu_primitives::{Boolean, Element, Endoscalar, Point, multiadd, multipack};
use std::hint::black_box;

fn bench_element_ops(c: &mut Criterion) {
    c.bench_function("primitives/element/mul", |b| {
        b.iter_batched(
            || setup_element_mul(mock_rng()),
            |(a, b)| {
                black_box(BenchEmulator::emulate_wireless((a, b), |dr, witness| {
                    let (a, b) = witness.cast();
                    let a = Element::alloc(dr, a)?;
                    let b = Element::alloc(dr, b)?;
                    a.mul(dr, &b)
                }));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/invert", |b| {
        b.iter_batched(
            || setup_element_invert(mock_rng()),
            |input| {
                black_box(BenchEmulator::emulate_wireless(input, |dr, witness| {
                    let a = Element::alloc(dr, witness)?;
                    a.invert(dr)
                }));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/fold_8", |b| {
        b.iter_batched(
            || setup_element_fold_8(mock_rng()),
            |(values, scale)| {
                black_box(BenchEmulator::emulate_wireless((values, scale), |dr, witness| {
                    let (vals, scale) = witness.cast();
                    let elements: Vec<_> = (0..8)
                        .map(|i| Element::alloc(dr, vals.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    let scale = Element::alloc(dr, scale)?;
                    Element::fold(dr, &elements, &scale)
                }));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/is_zero", |b| {
        b.iter_batched(
            || setup_element_is_zero(mock_rng()),
            |input| {
                black_box(BenchEmulator::emulate_wireless(input, |dr, witness| {
                    let a = Element::alloc(dr, witness)?;
                    a.is_zero(dr)
                }));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/multiadd_8", |b| {
        b.iter_batched(
            || setup_element_multiadd_8(mock_rng()),
            |(values, coeffs)| {
                black_box(BenchEmulator::emulate_wireless((values, coeffs), |dr, witness| {
                    let (vals, coeffs) = witness.cast();
                    let elements: Vec<_> = (0..8)
                        .map(|i| Element::alloc(dr, vals.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    let coeffs: Vec<_> = (0..8)
                        .map(|i| *coeffs.view().map(|c| c[i]).snag())
                        .collect();
                    multiadd(dr, &elements, &coeffs)
                }));
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_point_ops(c: &mut Criterion) {
    c.bench_function("primitives/point/double", |b| {
        b.iter_batched(
            || setup_point_single(mock_rng()),
            |point| {
                black_box(BenchEmulator::emulate_wireless(point, |dr, witness| {
                    let p = Point::alloc(dr, witness)?;
                    p.double(dr)
                }));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/point/add_incomplete", |b| {
        b.iter_batched(
            || setup_point_pair(mock_rng()),
            |points| {
                black_box(BenchEmulator::emulate_wireless(points, |dr, witness| {
                    let (p, q) = witness.cast();
                    let p = Point::alloc(dr, p)?;
                    let q = Point::alloc(dr, q)?;
                    p.add_incomplete(dr, &q, None)
                }));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/point/double_and_add_incomplete", |b| {
        b.iter_batched(
            || setup_point_pair(mock_rng()),
            |points| {
                black_box(BenchEmulator::emulate_wireless(points, |dr, witness| {
                    let (p, q) = witness.cast();
                    let p = Point::alloc(dr, p)?;
                    let q = Point::alloc(dr, q)?;
                    p.double_and_add_incomplete(dr, &q)
                }));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/point/endo", |b| {
        b.iter_batched(
            || setup_point_single(mock_rng()),
            |point| {
                black_box(BenchEmulator::emulate_wireless(point, |dr, witness| {
                    let p = Point::alloc(dr, witness)?;
                    p.endo(dr)
                }));
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_boolean_ops(c: &mut Criterion) {
    c.bench_function("primitives/boolean/multipack_256", |b| {
        b.iter_batched(
            || setup_bool_256(mock_rng()),
            |bits| {
                black_box(BenchEmulator::emulate_wireless(bits, |dr, witness| {
                    let bools: Vec<_> = (0..256)
                        .map(|i| Boolean::alloc(dr, witness.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    multipack(dr, &bools)
                }));
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_sponge_ops(c: &mut Criterion) {
    c.bench_function("primitives/sponge/absorb_squeeze", |b| {
        b.iter_batched(
            || setup_sponge(mock_rng()),
            |(input, poseidon)| {
                black_box(BenchEmulator::emulate_wireless(input, |dr, witness| {
                    let mut sponge = Sponge::new(dr, poseidon);
                    let elem = Element::alloc(dr, witness)?;
                    sponge.absorb(dr, &elem)?;
                    sponge.squeeze(dr)
                }));
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_endoscalar_ops(c: &mut Criterion) {
    c.bench_function("primitives/endoscalar/group_scale", |b| {
        b.iter_batched(
            || setup_group_scale(mock_rng()),
            |(point, scalar)| {
                black_box(BenchEmulator::emulate_wireless((point, scalar), |dr, witness| {
                    let (p, scalar) = witness.cast();
                    let p = Point::alloc(dr, p)?;
                    let scalar = Endoscalar::alloc(dr, scalar)?;
                    scalar.group_scale(dr, &p)
                }));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/endoscalar/extract", |b| {
        b.iter_batched(
            || setup_extract(mock_rng()),
            |input| {
                black_box(BenchEmulator::emulate_wireless(input, |dr, witness| {
                    let elem = Element::alloc(dr, witness)?;
                    Endoscalar::extract(dr, elem)
                }));
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/endoscalar/field_scale", |b| {
        b.iter_batched(
            || setup_field_scale(mock_rng()),
            |scalar| {
                black_box(BenchEmulator::emulate_wireless(scalar, |dr, witness| {
                    let scalar = Endoscalar::alloc(dr, witness)?;
                    scalar.field_scale(dr)
                }));
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group! {
    name = element_ops;
    config = Criterion::default();
    targets = bench_element_ops
}

criterion_group! {
    name = point_ops;
    config = Criterion::default();
    targets = bench_point_ops
}

criterion_group! {
    name = boolean_ops;
    config = Criterion::default();
    targets = bench_boolean_ops
}

criterion_group! {
    name = sponge_ops;
    config = Criterion::default();
    targets = bench_sponge_ops
}

criterion_group! {
    name = endoscalar_ops;
    config = Criterion::default();
    targets = bench_endoscalar_ops
}

criterion_main!(
    element_ops,
    point_ops,
    boolean_ops,
    sponge_ops,
    endoscalar_ops
);
