mod common;

use common::{
    mock_rng, setup_domain_ell, setup_dot, setup_eval, setup_factor, setup_fft, setup_geosum,
    setup_msm, setup_roots, DOT_SIZES, DOMAIN_ELL_K_VALUES, FACTOR_SIZES, FFT_K_VALUES,
    GEOSUM_SIZES, MSM_SIZES, POLY_EVAL_SIZES, POLY_ROOTS_SIZES,
};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use ragu_arithmetic::{dot, eval, factor, geosum, mul, poly_with_roots};
use std::hint::black_box;

fn bench_msm_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("arithmetic/msm");
    for &n in MSM_SIZES {
        group.bench_with_input(BenchmarkId::new("mul", n), &n, |b, &n| {
            b.iter_batched(
                || setup_msm(mock_rng(), n),
                |(coeffs, bases)| {
                    black_box(mul(coeffs.iter(), bases.iter()));
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_fft_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("arithmetic/fft");
    for &k in FFT_K_VALUES {
        group.bench_with_input(BenchmarkId::new("fft", format!("2_{k}")), &k, |b, &k| {
            b.iter_batched(
                || setup_fft(mock_rng(), k),
                |(domain, mut data)| {
                    domain.fft(&mut data);
                    black_box(data);
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_domain_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("arithmetic/domain");
    for &k in DOMAIN_ELL_K_VALUES {
        group.bench_with_input(BenchmarkId::new("ell", format!("2_{k}_full")), &k, |b, &k| {
            b.iter_batched(
                || setup_domain_ell(mock_rng(), k),
                |(domain, x, n)| {
                    black_box(domain.ell(x, n));
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_poly_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("arithmetic/poly");
    for &n in POLY_ROOTS_SIZES {
        group.bench_with_input(BenchmarkId::new("poly_with_roots", n), &n, |b, &n| {
            b.iter_batched(
                || setup_roots(mock_rng(), n),
                |roots| {
                    black_box(poly_with_roots(&roots));
                },
                BatchSize::SmallInput,
            )
        });
    }

    for &n in POLY_EVAL_SIZES {
        group.bench_with_input(BenchmarkId::new("eval", n), &n, |b, &n| {
            b.iter_batched(
                || setup_eval(mock_rng(), n),
                |(coeffs, x)| {
                    black_box(eval(&coeffs, x));
                },
                BatchSize::SmallInput,
            )
        });
    }

    for &n in FACTOR_SIZES {
        group.bench_with_input(BenchmarkId::new("factor", n), &n, |b, &n| {
            b.iter_batched(
                || setup_factor(mock_rng(), n),
                |(coeffs, x)| {
                    black_box(factor(coeffs, x));
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_field_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("arithmetic/field");
    for &n in DOT_SIZES {
        group.bench_with_input(BenchmarkId::new("dot", n), &n, |b, &n| {
            b.iter_batched(
                || setup_dot(mock_rng(), n),
                |(a, b)| {
                    black_box(dot(&a, &b));
                },
                BatchSize::SmallInput,
            )
        });
    }

    for &n in GEOSUM_SIZES {
        group.bench_with_input(BenchmarkId::new("geosum", n), &n, |b, &n| {
            b.iter_batched(
                || setup_geosum(mock_rng(), n),
                |(r, n)| {
                    black_box(geosum(r, n));
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group! {
    name = msm_ops;
    config = Criterion::default();
    targets = bench_msm_ops
}

criterion_group! {
    name = fft_ops;
    config = Criterion::default();
    targets = bench_fft_ops
}

criterion_group! {
    name = domain_ops;
    config = Criterion::default();
    targets = bench_domain_ops
}

criterion_group! {
    name = poly_ops;
    config = Criterion::default();
    targets = bench_poly_ops
}

criterion_group! {
    name = field_ops;
    config = Criterion::default();
    targets = bench_field_ops
}

criterion_main!(msm_ops, fft_ops, domain_ops, poly_ops, field_ops);
