use arithmetic::{Cycle, Uendo};
use ff::Field;
use group::prime::PrimeCurveAffine;
use gungraun::{library_benchmark, library_benchmark_group, main};
use ragu_core::drivers::emulator::{Emulator, Wireless};
use ragu_core::maybe::{Always, Maybe};
use ragu_pasta::{EpAffine, Fp, Fq, Pasta};
use ragu_primitives::poseidon::Sponge;
use ragu_primitives::{Boolean, Element, Endoscalar, Point, multiadd, multipack};
use rand::Rng;
use rand::rngs::mock::StepRng;
use std::hint::black_box;

fn mock_rng() -> StepRng {
    StepRng::new(u64::from_le_bytes(*b"12345666"), 0x1234_5666_1234_5666)
}

fn random_fp(rng: &mut impl Rng) -> Fp {
    Fp::random(rng)
}

fn random_point(rng: &mut impl Rng) -> EpAffine {
    (EpAffine::generator() * Fq::random(rng)).into()
}

fn random_fp_array<const N: usize>(rng: &mut impl Rng) -> [Fp; N] {
    core::array::from_fn(|_| Fp::random(&mut *rng))
}

fn random_bool_array<const N: usize>(rng: &mut impl Rng) -> [bool; N] {
    core::array::from_fn(|_| rng.r#gen())
}

fn random_uendo(rng: &mut impl Rng) -> Uendo {
    rng.r#gen()
}

type BenchEmulator = Emulator<Wireless<Always<()>, Fp>>;

fn setup_element_mul(mut rng: StepRng) -> (Fp, Fp) {
    (random_fp(&mut rng), random_fp(&mut rng))
}

fn setup_element_invert(mut rng: StepRng) -> Fp {
    random_fp(&mut rng)
}

fn setup_element_fold_8(mut rng: StepRng) -> ([Fp; 8], Fp) {
    (random_fp_array::<8>(&mut rng), random_fp(&mut rng))
}

fn setup_element_is_zero(mut rng: StepRng) -> Fp {
    random_fp(&mut rng)
}

fn setup_element_multiadd_8(mut rng: StepRng) -> ([Fp; 8], [Fp; 8]) {
    (
        random_fp_array::<8>(&mut rng),
        random_fp_array::<8>(&mut rng),
    )
}

fn setup_point_single(mut rng: StepRng) -> EpAffine {
    random_point(&mut rng)
}

fn setup_point_pair(mut rng: StepRng) -> (EpAffine, EpAffine) {
    (random_point(&mut rng), random_point(&mut rng))
}

fn setup_bool_256(mut rng: StepRng) -> [bool; 256] {
    random_bool_array::<256>(&mut rng)
}

fn setup_sponge(mut rng: StepRng) -> (Fp, &'static <Pasta as Cycle>::CircuitPoseidon) {
    let pasta = Pasta::baked();
    (random_fp(&mut rng), Pasta::circuit_poseidon(pasta))
}

fn setup_group_scale(mut rng: StepRng) -> (EpAffine, Uendo) {
    (random_point(&mut rng), random_uendo(&mut rng))
}

fn setup_extract(mut rng: StepRng) -> Fp {
    random_fp(&mut rng)
}

fn setup_field_scale(mut rng: StepRng) -> Uendo {
    random_uendo(&mut rng)
}

#[library_benchmark]
#[bench::mul(args = (mock_rng(),), setup = setup_element_mul)]
fn element_mul((a, b): (Fp, Fp)) {
    black_box(
        BenchEmulator::emulate_wireless((a, b), |dr, witness| {
            let (a, b) = witness.cast();
            let a = Element::alloc(dr, a)?;
            let b = Element::alloc(dr, b)?;
            a.mul(dr, &b)
        })
        .unwrap(),
    );
}

#[library_benchmark]
#[bench::invert(args = (mock_rng(),), setup = setup_element_invert)]
fn element_invert(input: Fp) {
    black_box(
        BenchEmulator::emulate_wireless(input, |dr, witness| {
            let a = Element::alloc(dr, witness)?;
            a.invert(dr)
        })
        .unwrap(),
    );
}

#[library_benchmark]
#[bench::fold_8(args = (mock_rng(),), setup = setup_element_fold_8)]
fn element_fold_8((values, scale): ([Fp; 8], Fp)) {
    black_box(
        BenchEmulator::emulate_wireless((values, scale), |dr, witness| {
            let (vals, scale) = witness.cast();
            let elements: Vec<_> = (0..8)
                .map(|i| Element::alloc(dr, vals.view().map(|v| v[i])))
                .collect::<Result<_, _>>()?;
            let scale = Element::alloc(dr, scale)?;
            Element::fold(dr, &elements, &scale)
        })
        .unwrap(),
    );
}

#[library_benchmark]
#[bench::is_zero(args = (mock_rng(),), setup = setup_element_is_zero)]
fn element_is_zero(input: Fp) {
    black_box(
        BenchEmulator::emulate_wireless(input, |dr, witness| {
            let a = Element::alloc(dr, witness)?;
            a.is_zero(dr)
        })
        .unwrap(),
    );
}

#[library_benchmark]
#[bench::multiadd_8(args = (mock_rng(),), setup = setup_element_multiadd_8)]
fn element_multiadd_8((values, coeffs): ([Fp; 8], [Fp; 8])) {
    black_box(
        BenchEmulator::emulate_wireless((values, coeffs), |dr, witness| {
            let (vals, coeffs) = witness.cast();
            let elements: Vec<_> = (0..8)
                .map(|i| Element::alloc(dr, vals.view().map(|v| v[i])))
                .collect::<Result<_, _>>()?;
            let coeffs: Vec<_> = (0..8)
                .map(|i| *coeffs.view().map(|c| c[i]).snag())
                .collect();
            multiadd(dr, &elements, &coeffs)
        })
        .unwrap(),
    );
}

library_benchmark_group!(
    name = element_ops;
    benchmarks = element_mul, element_invert, element_fold_8, element_is_zero, element_multiadd_8
);

#[library_benchmark]
#[bench::double(args = (mock_rng(),), setup = setup_point_single)]
fn point_double(point: EpAffine) {
    black_box(
        BenchEmulator::emulate_wireless(point, |dr, witness| {
            let p = Point::alloc(dr, witness)?;
            p.double(dr)
        })
        .unwrap(),
    );
}

#[library_benchmark]
#[bench::add_incomplete(args = (mock_rng(),), setup = setup_point_pair)]
fn point_add_incomplete(points: (EpAffine, EpAffine)) {
    black_box(
        BenchEmulator::emulate_wireless(points, |dr, witness| {
            let (p, q) = witness.cast();
            let p = Point::alloc(dr, p)?;
            let q = Point::alloc(dr, q)?;
            p.add_incomplete(dr, &q, None)
        })
        .unwrap(),
    );
}

#[library_benchmark]
#[bench::double_and_add(args = (mock_rng(),), setup = setup_point_pair)]
fn point_double_and_add_incomplete(points: (EpAffine, EpAffine)) {
    black_box(
        BenchEmulator::emulate_wireless(points, |dr, witness| {
            let (p, q) = witness.cast();
            let p = Point::alloc(dr, p)?;
            let q = Point::alloc(dr, q)?;
            p.double_and_add_incomplete(dr, &q)
        })
        .unwrap(),
    );
}

#[library_benchmark]
#[bench::endo(args = (mock_rng(),), setup = setup_point_single)]
fn point_endo(point: EpAffine) {
    black_box(
        BenchEmulator::emulate_wireless(point, |dr, witness| {
            let p = Point::alloc(dr, witness)?;
            p.endo(dr)
        })
        .unwrap(),
    );
}

library_benchmark_group!(
    name = point_ops;
    benchmarks = point_double, point_add_incomplete, point_double_and_add_incomplete, point_endo
);

#[library_benchmark]
#[bench::multipack_256(args = (mock_rng(),), setup = setup_bool_256)]
fn boolean_multipack_256(bits: [bool; 256]) {
    black_box(
        BenchEmulator::emulate_wireless(bits, |dr, witness| {
            let bools: Vec<_> = (0..256)
                .map(|i| Boolean::alloc(dr, witness.view().map(|v| v[i])))
                .collect::<Result<_, _>>()?;
            multipack(dr, &bools)
        })
        .unwrap(),
    );
}

library_benchmark_group!(
    name = boolean_ops;
    benchmarks = boolean_multipack_256
);

#[library_benchmark]
#[bench::absorb_squeeze(args = (mock_rng(),), setup = setup_sponge)]
fn sponge_absorb_squeeze(
    (input, poseidon): (Fp, &'static <ragu_pasta::Pasta as Cycle>::CircuitPoseidon),
) {
    black_box(
        BenchEmulator::emulate_wireless(input, |dr, witness| {
            let mut sponge = Sponge::new(dr, poseidon);
            let elem = Element::alloc(dr, witness)?;
            sponge.absorb(dr, &elem)?;
            sponge.squeeze(dr)
        })
        .unwrap(),
    );
}

library_benchmark_group!(
    name = sponge_ops;
    benchmarks = sponge_absorb_squeeze
);

#[library_benchmark]
#[bench::group_scale(args = (mock_rng(),), setup = setup_group_scale)]
fn endoscalar_group_scale((point, scalar): (EpAffine, Uendo)) {
    black_box(
        BenchEmulator::emulate_wireless((point, scalar), |dr, witness| {
            let (p, scalar) = witness.cast();
            let p = Point::alloc(dr, p)?;
            let scalar = Endoscalar::alloc(dr, scalar)?;
            scalar.group_scale(dr, &p)
        })
        .unwrap(),
    );
}

#[library_benchmark]
#[bench::extract(args = (mock_rng(),), setup = setup_extract)]
fn endoscalar_extract(input: Fp) {
    black_box(
        BenchEmulator::emulate_wireless(input, |dr, witness| {
            let elem = Element::alloc(dr, witness)?;
            Endoscalar::extract(dr, elem)
        })
        .unwrap(),
    );
}

#[library_benchmark]
#[bench::field_scale(args = (mock_rng(),), setup = setup_field_scale)]
fn endoscalar_field_scale(scalar: Uendo) {
    black_box(
        BenchEmulator::emulate_wireless(scalar, |dr, witness| {
            let scalar = Endoscalar::alloc(dr, witness)?;
            scalar.field_scale(dr)
        })
        .unwrap(),
    );
}

library_benchmark_group!(
    name = endoscalar_ops;
    benchmarks = endoscalar_group_scale, endoscalar_extract, endoscalar_field_scale
);

main!(
    library_benchmark_groups = element_ops,
    point_ops,
    boolean_ops,
    sponge_ops,
    endoscalar_ops
);
