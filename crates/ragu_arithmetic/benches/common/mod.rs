use ff::Field;
use pasta_curves::group::prime::PrimeCurveAffine;
use pasta_curves::{EpAffine, Fp, Fq};
use ragu_arithmetic::Domain;
use rand::Rng;
use rand::rngs::mock::StepRng;

// ============================================================================
// Size constants for parameterized benchmarks
// ============================================================================

pub const MSM_SIZES: &[usize] = &[64, 256, 1024, 4096];
pub const FFT_K_VALUES: &[u32] = &[10, 14, 18];
pub const DOMAIN_ELL_K_VALUES: &[u32] = &[10, 14];
pub const POLY_ROOTS_SIZES: &[usize] = &[16, 64, 256, 1024];
pub const POLY_EVAL_SIZES: &[usize] = &[256, 4096, 65536];
pub const FACTOR_SIZES: &[usize] = &[256, 4096];
pub const DOT_SIZES: &[usize] = &[256, 4096, 65536];
pub const GEOSUM_SIZES: &[usize] = &[256, 4096];

pub fn mock_rng() -> StepRng {
    StepRng::new(u64::from_le_bytes(*b"ynottryt"), 0xCA05_CA05_CA05_CA05)
}

// ============================================================================
// Primitive generators - building blocks for setup functions
// ============================================================================

/// Generate a vector of random Fp elements
pub fn random_fp_vec(rng: &mut impl Rng, n: usize) -> Vec<Fp> {
    (0..n).map(|_| Fp::random(&mut *rng)).collect()
}

/// Generate a vector of random Fq elements
pub fn random_fq_vec(rng: &mut impl Rng, n: usize) -> Vec<Fq> {
    (0..n).map(|_| Fq::random(&mut *rng)).collect()
}

/// Generate a vector of random curve points
pub fn random_points(rng: &mut impl Rng, n: usize) -> Vec<EpAffine> {
    (0..n)
        .map(|_| (EpAffine::generator() * Fq::random(&mut *rng)).into())
        .collect()
}

/// Generate a single random Fp element
pub fn random_fp(rng: &mut impl Rng) -> Fp {
    Fp::random(rng)
}

// ============================================================================
// MSM setup
// ============================================================================

pub fn setup_msm(mut rng: StepRng, n: usize) -> (Vec<Fq>, Vec<EpAffine>) {
    (random_fq_vec(&mut rng, n), random_points(&mut rng, n))
}

// ============================================================================
// FFT setup
// ============================================================================

pub fn setup_fft(mut rng: StepRng, k: u32) -> (Domain<Fp>, Vec<Fp>) {
    let domain = Domain::new(k);
    let data = random_fp_vec(&mut rng, domain.n());
    (domain, data)
}

// ============================================================================
// Domain setup
// ============================================================================

pub fn setup_domain_ell(mut rng: StepRng, k: u32) -> (Domain<Fp>, Fp, usize) {
    let domain = Domain::new(k);
    let n = domain.n();
    (domain, random_fp(&mut rng), n)
}

// ============================================================================
// Poly setup
// ============================================================================

pub fn setup_roots(mut rng: StepRng, n: usize) -> Vec<Fp> {
    random_fp_vec(&mut rng, n)
}

pub fn setup_eval(mut rng: StepRng, n: usize) -> (Vec<Fp>, Fp) {
    (random_fp_vec(&mut rng, n), random_fp(&mut rng))
}

pub fn setup_factor(mut rng: StepRng, n: usize) -> (Vec<Fp>, Fp) {
    (random_fp_vec(&mut rng, n), random_fp(&mut rng))
}

// ============================================================================
// Field ops setup
// ============================================================================

pub fn setup_dot(mut rng: StepRng, n: usize) -> (Vec<Fp>, Vec<Fp>) {
    (random_fp_vec(&mut rng, n), random_fp_vec(&mut rng, n))
}

pub fn setup_geosum(mut rng: StepRng, n: usize) -> (Fp, usize) {
    (random_fp(&mut rng), n)
}
