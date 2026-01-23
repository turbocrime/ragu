mod common;

use common::{
    mock_rng, setup_domain_ell, setup_dot, setup_eval, setup_factor, setup_fft, setup_geosum,
    setup_msm, setup_roots,
};
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use pasta_curves::{EpAffine, Fp, Fq};
use ragu_arithmetic::{Domain, dot, eval, factor, geosum, mul, poly_with_roots};

// ============================================================================
// MSM ops
// Size values match common::MSM_SIZES
// ============================================================================

#[library_benchmark]
#[bench::n64(args = (mock_rng(), 64), setup = setup_msm)]
#[bench::n256(args = (mock_rng(), 256), setup = setup_msm)]
#[bench::n1024(args = (mock_rng(), 1024), setup = setup_msm)]
#[bench::n4096(args = (mock_rng(), 4096), setup = setup_msm)]
fn msm_mul((coeffs, bases): (Vec<Fq>, Vec<EpAffine>)) {
    black_box(mul(coeffs.iter(), bases.iter()));
}

library_benchmark_group!(
    name = msm_ops;
    benchmarks = msm_mul
);

// ============================================================================
// FFT ops
// Size values match common::FFT_K_VALUES
// ============================================================================

#[library_benchmark]
#[bench::k10(args = (mock_rng(), 10), setup = setup_fft)]
#[bench::k14(args = (mock_rng(), 14), setup = setup_fft)]
#[bench::k18(args = (mock_rng(), 18), setup = setup_fft)]
fn fft((domain, mut data): (Domain<Fp>, Vec<Fp>)) {
    domain.fft(&mut data);
    black_box(data);
}

library_benchmark_group!(
    name = fft_ops;
    benchmarks = fft
);

// ============================================================================
// Domain ops
// Size values match common::DOMAIN_ELL_K_VALUES
// ============================================================================

#[library_benchmark]
#[bench::k10(args = (mock_rng(), 10), setup = setup_domain_ell)]
#[bench::k14(args = (mock_rng(), 14), setup = setup_domain_ell)]
fn domain_ell((domain, x, n): (Domain<Fp>, Fp, usize)) {
    black_box(domain.ell(x, n));
}

library_benchmark_group!(
    name = domain_ops;
    benchmarks = domain_ell
);

// ============================================================================
// Poly ops
// Size values match common::POLY_ROOTS_SIZES, POLY_EVAL_SIZES, FACTOR_SIZES
// ============================================================================

#[library_benchmark]
#[bench::n16(args = (mock_rng(), 16), setup = setup_roots)]
#[bench::n64(args = (mock_rng(), 64), setup = setup_roots)]
#[bench::n256(args = (mock_rng(), 256), setup = setup_roots)]
#[bench::n1024(args = (mock_rng(), 1024), setup = setup_roots)]
fn poly_with_roots_bench(roots: Vec<Fp>) {
    black_box(poly_with_roots(&roots));
}

#[library_benchmark]
#[bench::n256(args = (mock_rng(), 256), setup = setup_eval)]
#[bench::n4096(args = (mock_rng(), 4096), setup = setup_eval)]
#[bench::n65536(args = (mock_rng(), 65536), setup = setup_eval)]
fn poly_eval((coeffs, x): (Vec<Fp>, Fp)) {
    black_box(eval(&coeffs, x));
}

#[library_benchmark]
#[bench::n256(args = (mock_rng(), 256), setup = setup_factor)]
#[bench::n4096(args = (mock_rng(), 4096), setup = setup_factor)]
fn poly_factor((coeffs, x): (Vec<Fp>, Fp)) {
    black_box(factor(coeffs, x));
}

library_benchmark_group!(
    name = poly_ops;
    benchmarks = poly_with_roots_bench, poly_eval, poly_factor
);

// ============================================================================
// Field ops
// Size values match common::DOT_SIZES, GEOSUM_SIZES
// ============================================================================

#[library_benchmark]
#[bench::n256(args = (mock_rng(), 256), setup = setup_dot)]
#[bench::n4096(args = (mock_rng(), 4096), setup = setup_dot)]
#[bench::n65536(args = (mock_rng(), 65536), setup = setup_dot)]
fn field_dot((a, b): (Vec<Fp>, Vec<Fp>)) {
    black_box(dot(&a, &b));
}

#[library_benchmark]
#[bench::n256(args = (mock_rng(), 256), setup = setup_geosum)]
#[bench::n4096(args = (mock_rng(), 4096), setup = setup_geosum)]
fn field_geosum((r, n): (Fp, usize)) {
    black_box(geosum(r, n));
}

library_benchmark_group!(
    name = field_ops;
    benchmarks = field_dot, field_geosum
);

// ============================================================================
// Main
// ============================================================================

main!(
    library_benchmark_groups = msm_ops, fft_ops, domain_ops, poly_ops, field_ops
);
