use ff::Field;
use gungraun::{library_benchmark, library_benchmark_group, main};
use pasta_curves::group::prime::PrimeCurveAffine;
use pasta_curves::{EpAffine, Fp, Fq};
use ragu_arithmetic::{Domain, dot, eval, factor, geosum, mul, poly_with_roots};
use rand::Rng;
use rand::rngs::mock::StepRng;
use std::hint::black_box;

fn mock_rng() -> StepRng {
    StepRng::new(u64::from_le_bytes(*b"ynottryt"), 0xCA05_CA05_CA05_CA05)
}

fn random_fp_vec(rng: &mut impl Rng, n: usize) -> Vec<Fp> {
    (0..n).map(|_| Fp::random(&mut *rng)).collect()
}

fn random_fq_vec(rng: &mut impl Rng, n: usize) -> Vec<Fq> {
    (0..n).map(|_| Fq::random(&mut *rng)).collect()
}

fn random_points(rng: &mut impl Rng, n: usize) -> Vec<EpAffine> {
    (0..n)
        .map(|_| (EpAffine::generator() * Fq::random(&mut *rng)).into())
        .collect()
}

fn random_fp(rng: &mut impl Rng) -> Fp {
    Fp::random(rng)
}

fn setup_msm(mut rng: StepRng, n: usize) -> (Vec<Fq>, Vec<EpAffine>) {
    (random_fq_vec(&mut rng, n), random_points(&mut rng, n))
}

fn setup_fft(mut rng: StepRng, k: u32) -> (Domain<Fp>, Vec<Fp>) {
    let domain = Domain::new(k);
    let data = random_fp_vec(&mut rng, domain.n());
    (domain, data)
}

fn setup_domain_ell(mut rng: StepRng, k: u32) -> (Domain<Fp>, Fp, usize) {
    let domain = Domain::new(k);
    let n = domain.n();
    (domain, random_fp(&mut rng), n)
}

fn setup_roots(mut rng: StepRng, n: usize) -> Vec<Fp> {
    random_fp_vec(&mut rng, n)
}

fn setup_eval(mut rng: StepRng, n: usize) -> (Vec<Fp>, Fp) {
    (random_fp_vec(&mut rng, n), random_fp(&mut rng))
}

fn setup_factor(mut rng: StepRng, n: usize) -> (Vec<Fp>, Fp) {
    (random_fp_vec(&mut rng, n), random_fp(&mut rng))
}

fn setup_dot(mut rng: StepRng, n: usize) -> (Vec<Fp>, Vec<Fp>) {
    (random_fp_vec(&mut rng, n), random_fp_vec(&mut rng, n))
}

fn setup_geosum(mut rng: StepRng, n: usize) -> (Fp, usize) {
    (random_fp(&mut rng), n)
}

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

#[library_benchmark]
#[bench::k10(args = (mock_rng(), 10), setup = setup_fft)]
#[bench::k14(args = (mock_rng(), 14), setup = setup_fft)]
#[bench::k18(args = (mock_rng(), 18), setup = setup_fft)]
fn fft((domain, mut data): (Domain<Fp>, Vec<Fp>)) {
    domain.fft(&mut data);
    black_box(data);
}

#[library_benchmark]
#[bench::k10(args = (mock_rng(), 10), setup = setup_domain_ell)]
#[bench::k14(args = (mock_rng(), 14), setup = setup_domain_ell)]
fn ell((domain, x, n): (Domain<Fp>, Fp, usize)) {
    black_box(domain.ell(x, n));
}

library_benchmark_group!(
    name = domain_ops;
    benchmarks = fft, ell
);

#[library_benchmark]
#[bench::n16(args = (mock_rng(), 16), setup = setup_roots)]
#[bench::n64(args = (mock_rng(), 64), setup = setup_roots)]
#[bench::n256(args = (mock_rng(), 256), setup = setup_roots)]
#[bench::n1024(args = (mock_rng(), 1024), setup = setup_roots)]
fn with_roots(roots: Vec<Fp>) {
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
    benchmarks = with_roots, poly_eval, poly_factor
);

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

main!(
    library_benchmark_groups = msm_ops,
    domain_ops,
    poly_ops,
    field_ops
);
