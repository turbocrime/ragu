use arithmetic::{Cycle, Uendo};
use ff::Field;
use group::prime::PrimeCurveAffine;
use ragu_core::drivers::emulator::{Emulator, Wireless};
use ragu_core::maybe::Always;
use ragu_pasta::{EpAffine, Fp, Fq, Pasta};
use rand::Rng;
use rand::rngs::mock::StepRng;

pub fn mock_rng() -> StepRng {
    StepRng::new(u64::from_le_bytes(*b"12345666"), 0x1234_5666_1234_5666)
}

// ============================================================================
// Primitive generators - building blocks for setup functions
// ============================================================================

pub fn random_fp(rng: &mut impl Rng) -> Fp {
    Fp::random(rng)
}

pub fn random_point(rng: &mut impl Rng) -> EpAffine {
    (EpAffine::generator() * Fq::random(rng)).into()
}

pub fn random_fp_array<const N: usize>(rng: &mut impl Rng) -> [Fp; N] {
    core::array::from_fn(|_| Fp::random(&mut *rng))
}

pub fn random_bool_array<const N: usize>(rng: &mut impl Rng) -> [bool; N] {
    core::array::from_fn(|_| rng.r#gen())
}

pub fn random_uendo(rng: &mut impl Rng) -> Uendo {
    rng.r#gen()
}

pub type BenchEmulator = Emulator<Wireless<Always<()>, Fp>>;

// ============================================================================
// Element ops setup
// ============================================================================

pub fn setup_element_mul(mut rng: StepRng) -> (Fp, Fp) {
    (random_fp(&mut rng), random_fp(&mut rng))
}

pub fn setup_element_invert(mut rng: StepRng) -> Fp {
    random_fp(&mut rng)
}

pub fn setup_element_fold_8(mut rng: StepRng) -> ([Fp; 8], Fp) {
    (random_fp_array::<8>(&mut rng), random_fp(&mut rng))
}

pub fn setup_element_is_zero(mut rng: StepRng) -> Fp {
    random_fp(&mut rng)
}

pub fn setup_element_multiadd_8(mut rng: StepRng) -> ([Fp; 8], [Fp; 8]) {
    (random_fp_array::<8>(&mut rng), random_fp_array::<8>(&mut rng))
}

// ============================================================================
// Point ops setup
// ============================================================================

pub fn setup_point_single(mut rng: StepRng) -> EpAffine {
    random_point(&mut rng)
}

pub fn setup_point_pair(mut rng: StepRng) -> (EpAffine, EpAffine) {
    (random_point(&mut rng), random_point(&mut rng))
}

// ============================================================================
// Boolean ops setup
// ============================================================================

pub fn setup_bool_256(mut rng: StepRng) -> [bool; 256] {
    random_bool_array::<256>(&mut rng)
}

// ============================================================================
// Sponge ops setup
// ============================================================================

pub fn setup_sponge(mut rng: StepRng) -> (Fp, &'static <Pasta as Cycle>::CircuitPoseidon) {
    let pasta = Pasta::baked();
    (random_fp(&mut rng), Pasta::circuit_poseidon(pasta))
}

// ============================================================================
// Endoscalar ops setup
// ============================================================================

pub fn setup_group_scale(mut rng: StepRng) -> (EpAffine, Uendo) {
    (random_point(&mut rng), random_uendo(&mut rng))
}

pub fn setup_extract(mut rng: StepRng) -> Fp {
    random_fp(&mut rng)
}

pub fn setup_field_scale(mut rng: StepRng) -> Uendo {
    random_uendo(&mut rng)
}
