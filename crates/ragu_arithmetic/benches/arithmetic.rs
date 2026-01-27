mod setup;

use ff::Field;
use gungraun::{library_benchmark, library_benchmark_group, main};
use pasta_curves::{EpAffine, Fp, Fq};
use ragu_arithmetic::{Domain, dot, eval, factor, geosum, mul, poly_with_roots};
use setup::{
    mock_rng, random_fp, random_fp_vec, random_fq_vec, random_points, setup_rng, setup_with_rng,
};
use std::hint::black_box;

fn setup_domain_fft(k: u32) -> (Domain<Fp>, Vec<Fp>) {
    let mut rng = mock_rng();
    let domain = Domain::new(k);
    let data = (0..domain.n()).map(|_| Fp::random(&mut rng)).collect();
    (domain, data)
}

fn setup_domain_ell(k: u32) -> (Domain<Fp>, Fp, usize) {
    let mut rng = mock_rng();
    let domain = Domain::new(k);
    let n = domain.n();
    (domain, Fp::random(&mut rng), n)
}

#[library_benchmark(setup = setup_rng)]
#[bench::n64((random_fq_vec::<64>, random_points::<64>))]
#[bench::n256((random_fq_vec::<256>, random_points::<256>))]
#[bench::n1024((random_fq_vec::<1024>, random_points::<1024>))]
#[bench::n4096((random_fq_vec::<4096>, random_points::<4096>))]
fn msm_mul((coeffs, bases): (Vec<Fq>, Vec<EpAffine>)) {
    black_box(mul(coeffs.iter(), bases.iter()));
}

library_benchmark_group!(
    name = msm_ops;
    benchmarks = msm_mul
);

#[library_benchmark(setup = setup_domain_fft)]
#[bench::k10(10)]
#[bench::k14(14)]
#[bench::k18(18)]
fn fft((domain, mut data): (Domain<Fp>, Vec<Fp>)) {
    domain.fft(&mut data);
    black_box(data);
}

#[library_benchmark(setup = setup_domain_ell)]
#[bench::k10(10)]
#[bench::k14(14)]
fn ell((domain, x, n): (Domain<Fp>, Fp, usize)) {
    black_box(domain.ell(x, n));
}

library_benchmark_group!(
    name = domain_ops;
    benchmarks = fft, ell
);

#[library_benchmark(setup = setup_rng)]
#[bench::n16((random_fp_vec::<16>,))]
#[bench::n64((random_fp_vec::<64>,))]
#[bench::n256((random_fp_vec::<256>,))]
#[bench::n1024((random_fp_vec::<1024>,))]
fn with_roots((roots,): (Vec<Fp>,)) {
    black_box(poly_with_roots(&roots));
}

#[library_benchmark(setup = setup_rng)]
#[bench::n256((random_fp_vec::<256>, random_fp))]
#[bench::n4096((random_fp_vec::<4096>, random_fp))]
#[bench::n65536((random_fp_vec::<65536>, random_fp))]
fn poly_eval((coeffs, x): (Vec<Fp>, Fp)) {
    black_box(eval(&coeffs, x));
}

#[library_benchmark(setup = setup_rng)]
#[bench::n256((random_fp_vec::<256>, random_fp))]
#[bench::n4096((random_fp_vec::<4096>, random_fp))]
fn poly_factor((coeffs, x): (Vec<Fp>, Fp)) {
    black_box(factor(coeffs, x));
}

library_benchmark_group!(
    name = poly_ops;
    benchmarks = with_roots, poly_eval, poly_factor
);

#[library_benchmark(setup = setup_rng)]
#[bench::n256((random_fp_vec::<256>, random_fp_vec::<256>))]
#[bench::n4096((random_fp_vec::<4096>, random_fp_vec::<4096>))]
#[bench::n65536((random_fp_vec::<65536>, random_fp_vec::<65536>))]
fn field_dot((a, b): (Vec<Fp>, Vec<Fp>)) {
    black_box(dot(&a, &b));
}

#[library_benchmark(setup = setup_with_rng)]
#[bench::n256(256, (random_fp,))]
#[bench::n4096(4096, (random_fp,))]
fn field_geosum((n, (r,)): (usize, (Fp,))) {
    black_box(geosum(r, n));
}

library_benchmark_group!(
    name = field_ops;
    benchmarks = field_dot, field_geosum
);

main!(
    library_benchmark_groups = msm_ops,
    domain_ops,
    poly_ops,
    field_ops
);
