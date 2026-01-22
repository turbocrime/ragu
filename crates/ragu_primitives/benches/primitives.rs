use arithmetic::{Cycle, Uendo};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ff::Field;
use group::prime::PrimeCurveAffine;
use ragu_core::drivers::emulator::{Emulator, Wireless};
use ragu_core::maybe::{Always, Maybe};
use ragu_pasta::{EpAffine, Fp, Fq, Pasta};
use ragu_primitives::poseidon::Sponge;
use ragu_primitives::{Boolean, Element, Endoscalar, Point, multiadd, multipack};
use rand::Rng;
use rand::rngs::mock::StepRng;

type BenchEmulator = Emulator<Wireless<Always<()>, Fp>>;

fn mock_rng() -> StepRng {
    let seed_bytes: [u8; 8] = "12345666".as_bytes().try_into().unwrap();
    StepRng::new(u64::from_le_bytes(seed_bytes), 0x1234_5666_1234_5666)
}

fn bench_element_ops(c: &mut Criterion) {
    let mut rng = mock_rng();

    c.bench_function("primitives/element/mul", |b| {
        b.iter_batched(
            || (Fp::random(&mut rng), Fp::random(&mut rng)),
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (a, b) = witness.cast();
                    let a = Element::alloc(dr, a)?;
                    let b = Element::alloc(dr, b)?;
                    a.mul(dr, &b)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/square", |b| {
        b.iter_batched(
            || Fp::random(&mut rng),
            |input| {
                BenchEmulator::emulate_wireless(input, |dr, witness| {
                    let a = Element::alloc(dr, witness)?;
                    a.square(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/invert", |b| {
        b.iter_batched(
            || Fp::random(&mut rng),
            |input| {
                BenchEmulator::emulate_wireless(input, |dr, witness| {
                    let a = Element::alloc(dr, witness)?;
                    a.invert(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/fold_8", |b| {
        b.iter_batched(
            || {
                let values: [Fp; 8] = core::array::from_fn(|_| Fp::random(&mut rng));
                let scale = Fp::random(&mut rng);
                (values, scale)
            },
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (vals, scale) = witness.cast();
                    let elements: Vec<_> = (0..8)
                        .map(|i| Element::alloc(dr, vals.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    let scale = Element::alloc(dr, scale)?;
                    Element::fold(dr, &elements, &scale)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/fold_16", |b| {
        b.iter_batched(
            || {
                let values: [Fp; 16] = core::array::from_fn(|_| Fp::random(&mut rng));
                let scale = Fp::random(&mut rng);
                (values, scale)
            },
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (vals, scale) = witness.cast();
                    let elements: Vec<_> = (0..16)
                        .map(|i| Element::alloc(dr, vals.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    let scale = Element::alloc(dr, scale)?;
                    Element::fold(dr, &elements, &scale)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/fold_32", |b| {
        b.iter_batched(
            || {
                let values: [Fp; 32] = core::array::from_fn(|_| Fp::random(&mut rng));
                let scale = Fp::random(&mut rng);
                (values, scale)
            },
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (vals, scale) = witness.cast();
                    let elements: Vec<_> = (0..32)
                        .map(|i| Element::alloc(dr, vals.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    let scale = Element::alloc(dr, scale)?;
                    Element::fold(dr, &elements, &scale)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/fold_64", |b| {
        b.iter_batched(
            || {
                let values: [Fp; 64] = core::array::from_fn(|_| Fp::random(&mut rng));
                let scale = Fp::random(&mut rng);
                (values, scale)
            },
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (vals, scale) = witness.cast();
                    let elements: Vec<_> = (0..64)
                        .map(|i| Element::alloc(dr, vals.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    let scale = Element::alloc(dr, scale)?;
                    Element::fold(dr, &elements, &scale)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/is_zero", |b| {
        b.iter_batched(
            || Fp::random(&mut rng),
            |input| {
                BenchEmulator::emulate_wireless(input, |dr, witness| {
                    let a = Element::alloc(dr, witness)?;
                    a.is_zero(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/is_equal", |b| {
        b.iter_batched(
            || (Fp::random(&mut rng), Fp::random(&mut rng)),
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (a, b) = witness.cast();
                    let a = Element::alloc(dr, a)?;
                    let b = Element::alloc(dr, b)?;
                    a.is_equal(dr, &b)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/div_nonzero", |b| {
        b.iter_batched(
            || {
                let mut b = Fp::random(&mut rng);
                while b.is_zero().into() {
                    b = Fp::random(&mut rng);
                }
                (Fp::random(&mut rng), b)
            },
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (a, b) = witness.cast();
                    let a = Element::alloc(dr, a)?;
                    let b = Element::alloc(dr, b)?;
                    a.div_nonzero(dr, &b)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/multiadd_4", |b| {
        b.iter_batched(
            || {
                let values: [Fp; 4] = core::array::from_fn(|_| Fp::random(&mut rng));
                let coeffs: [Fp; 4] = core::array::from_fn(|_| Fp::random(&mut rng));
                (values, coeffs)
            },
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (vals, coeffs) = witness.cast();
                    let elements: Vec<_> = (0..4)
                        .map(|i| Element::alloc(dr, vals.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    let coeffs: Vec<_> = (0..4)
                        .map(|i| *coeffs.view().map(|c| c[i]).snag())
                        .collect();
                    multiadd(dr, &elements, &coeffs)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/element/multiadd_8", |b| {
        b.iter_batched(
            || {
                let values: [Fp; 8] = core::array::from_fn(|_| Fp::random(&mut rng));
                let coeffs: [Fp; 8] = core::array::from_fn(|_| Fp::random(&mut rng));
                (values, coeffs)
            },
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (vals, coeffs) = witness.cast();
                    let elements: Vec<_> = (0..8)
                        .map(|i| Element::alloc(dr, vals.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    let coeffs: Vec<_> = (0..8)
                        .map(|i| *coeffs.view().map(|c| c[i]).snag())
                        .collect();
                    multiadd(dr, &elements, &coeffs)
                })
            },
            BatchSize::SmallInput,
        )
    });
}

fn random_point(rng: &mut impl Rng) -> EpAffine {
    (EpAffine::generator() * Fq::random(rng)).into()
}

fn bench_point_ops(c: &mut Criterion) {
    let mut rng = mock_rng();

    c.bench_function("primitives/point/alloc", |b| {
        b.iter_batched(
            || random_point(&mut rng),
            |point| BenchEmulator::emulate_wireless(point, Point::alloc),
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/point/double", |b| {
        b.iter_batched(
            || random_point(&mut rng),
            |point| {
                BenchEmulator::emulate_wireless(point, |dr, witness| {
                    let p = Point::alloc(dr, witness)?;
                    p.double(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/point/add_incomplete", |b| {
        b.iter_batched(
            || (random_point(&mut rng), random_point(&mut rng)),
            |points| {
                BenchEmulator::emulate_wireless(points, |dr, witness| {
                    let (p, q) = witness.cast();
                    let p = Point::alloc(dr, p)?;
                    let q = Point::alloc(dr, q)?;
                    p.add_incomplete(dr, &q, None)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/point/double_and_add_incomplete", |b| {
        b.iter_batched(
            || (random_point(&mut rng), random_point(&mut rng)),
            |points| {
                BenchEmulator::emulate_wireless(points, |dr, witness| {
                    let (p, q) = witness.cast();
                    let p = Point::alloc(dr, p)?;
                    let q = Point::alloc(dr, q)?;
                    p.double_and_add_incomplete(dr, &q)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/point/endo", |b| {
        b.iter_batched(
            || random_point(&mut rng),
            |point| {
                BenchEmulator::emulate_wireless(point, |dr, witness| {
                    let p = Point::alloc(dr, witness)?;
                    p.endo(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/point/negate", |b| {
        b.iter_batched(
            || random_point(&mut rng),
            |point| {
                BenchEmulator::emulate_wireless(point, |dr, witness| {
                    let p = Point::alloc(dr, witness)?;
                    Ok(p.negate(dr))
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/point/conditional_negate", |b| {
        b.iter_batched(
            || (random_point(&mut rng), rng.r#gen::<bool>()),
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (p, cond) = witness.cast();
                    let p = Point::alloc(dr, p)?;
                    let cond = Boolean::alloc(dr, cond)?;
                    p.conditional_negate(dr, &cond)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/point/conditional_endo", |b| {
        b.iter_batched(
            || (random_point(&mut rng), rng.r#gen::<bool>()),
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (p, cond) = witness.cast();
                    let p = Point::alloc(dr, p)?;
                    let cond = Boolean::alloc(dr, cond)?;
                    p.conditional_endo(dr, &cond)
                })
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_boolean_ops(c: &mut Criterion) {
    let mut rng = mock_rng();

    c.bench_function("primitives/boolean/alloc", |b| {
        b.iter_batched(
            || rng.r#gen::<bool>(),
            |bit| BenchEmulator::emulate_wireless(bit, Boolean::alloc),
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/boolean/and", |b| {
        b.iter_batched(
            || (rng.r#gen::<bool>(), rng.r#gen::<bool>()),
            |bits| {
                BenchEmulator::emulate_wireless(bits, |dr, witness| {
                    let (a, b) = witness.cast();
                    let a = Boolean::alloc(dr, a)?;
                    let b = Boolean::alloc(dr, b)?;
                    a.and(dr, &b)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/boolean/conditional_select", |b| {
        b.iter_batched(
            || {
                (
                    rng.r#gen::<bool>(),
                    Fp::random(&mut rng),
                    Fp::random(&mut rng),
                )
            },
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (cond, a, b) = witness.cast();
                    let cond = Boolean::alloc(dr, cond)?;
                    let a = Element::alloc(dr, a)?;
                    let b = Element::alloc(dr, b)?;
                    cond.conditional_select(dr, &a, &b)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/boolean/multipack_256", |b| {
        b.iter_batched(
            || core::array::from_fn::<bool, 256, _>(|_| rng.r#gen()),
            |bits| {
                BenchEmulator::emulate_wireless(bits, |dr, witness| {
                    let bools: Vec<_> = (0..256)
                        .map(|i| Boolean::alloc(dr, witness.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    multipack(dr, &bools)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/boolean/conditional_enforce_equal", |b| {
        b.iter_batched(
            || {
                let cond = rng.r#gen::<bool>();
                let a = Fp::random(&mut rng);
                // When cond is true, b must equal a for the constraint to pass
                let b = if cond { a } else { Fp::random(&mut rng) };
                (cond, a, b)
            },
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (cond, a, b) = witness.cast();
                    let cond = Boolean::alloc(dr, cond)?;
                    let a = Element::alloc(dr, a)?;
                    let b = Element::alloc(dr, b)?;
                    cond.conditional_enforce_equal(dr, &a, &b)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/boolean/multipack_128", |b| {
        b.iter_batched(
            || core::array::from_fn::<bool, 128, _>(|_| rng.r#gen()),
            |bits| {
                BenchEmulator::emulate_wireless(bits, |dr, witness| {
                    let bools: Vec<_> = (0..128)
                        .map(|i| Boolean::alloc(dr, witness.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    multipack(dr, &bools)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/boolean/multipack_512", |b| {
        b.iter_batched(
            || core::array::from_fn::<bool, 512, _>(|_| rng.r#gen()),
            |bits| {
                BenchEmulator::emulate_wireless(bits, |dr, witness| {
                    let bools: Vec<_> = (0..512)
                        .map(|i| Boolean::alloc(dr, witness.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    multipack(dr, &bools)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/boolean/multipack_1000", |b| {
        b.iter_batched(
            || {
                let mut bits = [false; 1000];
                for bit in &mut bits {
                    *bit = rng.r#gen();
                }
                bits
            },
            |bits| {
                BenchEmulator::emulate_wireless(bits, |dr, witness| {
                    let bools: Vec<_> = (0..1000)
                        .map(|i| Boolean::alloc(dr, witness.view().map(|v| v[i])))
                        .collect::<Result<_, _>>()?;
                    multipack(dr, &bools)
                })
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_sponge_ops(c: &mut Criterion) {
    let pasta = Pasta::baked();
    let poseidon = Pasta::circuit_poseidon(pasta);
    let mut rng = mock_rng();

    c.bench_function("primitives/sponge/absorb_squeeze", |b| {
        b.iter_batched(
            || Fp::random(&mut rng),
            |input| {
                BenchEmulator::emulate_wireless(input, |dr, witness| {
                    let mut sponge = Sponge::new(dr, poseidon);
                    let elem = Element::alloc(dr, witness)?;
                    sponge.absorb(dr, &elem)?;
                    sponge.squeeze(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/sponge/absorb_3_squeeze", |b| {
        b.iter_batched(
            || core::array::from_fn::<Fp, 3, _>(|_| Fp::random(&mut rng)),
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let mut sponge = Sponge::new(dr, poseidon);
                    for i in 0..3 {
                        let elem = Element::alloc(dr, witness.view().map(|v| v[i]))?;
                        sponge.absorb(dr, &elem)?;
                    }
                    sponge.squeeze(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/sponge/absorb_6_squeeze", |b| {
        b.iter_batched(
            || core::array::from_fn::<Fp, 6, _>(|_| Fp::random(&mut rng)),
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let mut sponge = Sponge::new(dr, poseidon);
                    for i in 0..6 {
                        let elem = Element::alloc(dr, witness.view().map(|v| v[i]))?;
                        sponge.absorb(dr, &elem)?;
                    }
                    sponge.squeeze(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/sponge/absorb_9_squeeze", |b| {
        b.iter_batched(
            || core::array::from_fn::<Fp, 9, _>(|_| Fp::random(&mut rng)),
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let mut sponge = Sponge::new(dr, poseidon);
                    for i in 0..9 {
                        let elem = Element::alloc(dr, witness.view().map(|v| v[i]))?;
                        sponge.absorb(dr, &elem)?;
                    }
                    sponge.squeeze(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_endoscalar_ops(c: &mut Criterion) {
    let mut rng = mock_rng();

    c.bench_function("primitives/endoscalar/alloc", |b| {
        b.iter_batched(
            || rng.r#gen::<Uendo>(),
            |scalar| {
                BenchEmulator::emulate_wireless(scalar, |dr, witness| {
                    Endoscalar::alloc(dr, witness)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/endoscalar/group_scale", |b| {
        b.iter_batched(
            || (random_point(&mut rng), rng.r#gen::<Uendo>()),
            |inputs| {
                BenchEmulator::emulate_wireless(inputs, |dr, witness| {
                    let (p, scalar) = witness.cast();
                    let p = Point::alloc(dr, p)?;
                    let scalar = Endoscalar::alloc(dr, scalar)?;
                    scalar.group_scale(dr, &p)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/endoscalar/extract", |b| {
        b.iter_batched(
            || Fp::random(&mut rng),
            |input| {
                BenchEmulator::emulate_wireless(input, |dr, witness| {
                    let elem = Element::alloc(dr, witness)?;
                    Endoscalar::extract(dr, elem)
                })
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("primitives/endoscalar/field_scale", |b| {
        b.iter_batched(
            || rng.r#gen::<Uendo>(),
            |scalar| {
                BenchEmulator::emulate_wireless(scalar, |dr, witness| {
                    let scalar = Endoscalar::alloc(dr, witness)?;
                    scalar.field_scale(dr)
                })
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group! {
    name = endoscalar_ops;
    config = Criterion::default();
    targets = bench_endoscalar_ops
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

criterion_main!(
    element_ops,
    point_ops,
    boolean_ops,
    sponge_ops,
    endoscalar_ops
);
