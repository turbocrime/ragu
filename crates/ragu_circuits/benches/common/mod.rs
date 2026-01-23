use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::polynomials::{R, structured, unstructured};
use ragu_pasta::{Fp, Pasta};
use rand::rngs::mock::StepRng;

pub fn mock_rng() -> StepRng {
    StepRng::new(u64::from_le_bytes(*b"didnothn"), 0xF2EE_CAFE_D00D_2DA7)
}

// ============================================================================
// Poly commits setup
// ============================================================================

pub fn setup_structured(
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

pub fn setup_unstructured(
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

// ============================================================================
// Poly ops setup
// ============================================================================

pub fn setup_revdot(
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

pub fn setup_fold(mut rng: StepRng) -> (Vec<structured::Polynomial<Fp, R<13>>>, Fp) {
    let polys: Vec<_> = (0..8)
        .map(|_| structured::Polynomial::<Fp, R<13>>::random(&mut rng))
        .collect();
    (polys, Fp::random(&mut rng))
}

pub fn setup_eval(mut rng: StepRng) -> (structured::Polynomial<Fp, R<13>>, Fp) {
    (
        structured::Polynomial::random(&mut rng),
        Fp::random(&mut rng),
    )
}

pub fn setup_dilate(mut rng: StepRng) -> (structured::Polynomial<Fp, R<13>>, Fp) {
    (
        structured::Polynomial::random(&mut rng),
        Fp::random(&mut rng),
    )
}

// ============================================================================
// Circuit synthesis setup
// ============================================================================

pub fn setup_circuit_rx(mut rng: StepRng) -> ((Fp, Fp), Fp) {
    (
        (Fp::random(&mut rng), Fp::random(&mut rng)),
        Fp::random(&mut rng),
    )
}

pub fn setup_circuit_ky(mut rng: StepRng) -> (Fp, Fp) {
    (Fp::random(&mut rng), Fp::random(&mut rng))
}

pub fn setup_square_circuit_rx(mut rng: StepRng) -> (Fp, Fp) {
    (Fp::random(&mut rng), Fp::random(&mut rng))
}

// ============================================================================
// Registry ops setup
// ============================================================================

pub fn setup_registry_xy(mut rng: StepRng) -> (Fp, Fp) {
    (Fp::random(&mut rng), Fp::random(&mut rng))
}

pub fn setup_registry_wxy(mut rng: StepRng) -> (Fp, Fp, Fp) {
    (
        Fp::random(&mut rng),
        Fp::random(&mut rng),
        Fp::random(&mut rng),
    )
}
