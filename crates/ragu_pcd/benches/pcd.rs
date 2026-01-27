#![allow(clippy::type_complexity)]

use arithmetic::Cycle;
use gungraun::{library_benchmark, library_benchmark_group, main};
use ragu_circuits::polynomials::R;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::test_fixtures::nontrivial;
use ragu_pcd::{Application, ApplicationBuilder, Pcd};
use rand::rngs::mock::StepRng;
use std::hint::black_box;

fn mock_rng() -> StepRng {
    StepRng::new(u64::from_le_bytes(*b"innocent"), 0xF2EE_CAFE_BABE_2DA7)
}

fn setup_application_build() -> (
    &'static <Pasta as Cycle>::Params,
    &'static <Pasta as Cycle>::CircuitPoseidon,
) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    (pasta, poseidon_params)
}

fn setup_seed() -> (
    Application<'static, Pasta, R<13>, 4>,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StepRng,
) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap()
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap()
        .finalize(pasta)
        .unwrap();
    (app, poseidon_params, mock_rng())
}

fn setup_fuse() -> (
    Application<'static, Pasta, R<13>, 4>,
    Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
    Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StepRng,
) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap()
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap()
        .finalize(pasta)
        .unwrap();
    let mut rng = mock_rng();

    let (proof1, aux1) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(1u64),
        )
        .unwrap();
    let leaf1 = proof1.carry::<nontrivial::LeafNode>(aux1);

    let (proof2, aux2) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(2u64),
        )
        .unwrap();
    let leaf2 = proof2.carry::<nontrivial::LeafNode>(aux2);

    (app, leaf1, leaf2, poseidon_params, mock_rng())
}

fn setup_verify_leaf() -> (
    Application<'static, Pasta, R<13>, 4>,
    Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
    StepRng,
) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap()
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap()
        .finalize(pasta)
        .unwrap();
    let mut rng = mock_rng();

    let (proof, aux) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(1u64),
        )
        .unwrap();
    let leaf = proof.carry::<nontrivial::LeafNode>(aux);

    (app, leaf, mock_rng())
}

fn setup_verify_node() -> (
    Application<'static, Pasta, R<13>, 4>,
    Pcd<'static, Pasta, R<13>, nontrivial::InternalNode>,
    StepRng,
) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap()
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap()
        .finalize(pasta)
        .unwrap();
    let mut rng = mock_rng();

    let (proof1, aux1) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(1u64),
        )
        .unwrap();
    let leaf1 = proof1.carry::<nontrivial::LeafNode>(aux1);

    let (proof2, aux2) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(2u64),
        )
        .unwrap();
    let leaf2 = proof2.carry::<nontrivial::LeafNode>(aux2);

    let (proof, aux) = app
        .fuse(
            &mut rng,
            nontrivial::Hash2 { poseidon_params },
            (),
            leaf1,
            leaf2,
        )
        .unwrap();
    let node = proof.carry::<nontrivial::InternalNode>(aux);

    (app, node, mock_rng())
}

#[library_benchmark]
#[bench::application_build(setup = setup_application_build)]
fn application_build(
    (pasta, poseidon_params): (
        &'static <Pasta as Cycle>::Params,
        &'static <Pasta as Cycle>::CircuitPoseidon,
    ),
) {
    black_box(
        ApplicationBuilder::<Pasta, R<13>, 4>::new()
            .register(nontrivial::WitnessLeaf { poseidon_params })
            .unwrap()
            .register(nontrivial::Hash2 { poseidon_params })
            .unwrap()
            .finalize(pasta)
            .unwrap(),
    );
}

#[library_benchmark]
#[bench::seed(setup = setup_seed)]
fn seed(
    (app, poseidon_params, mut rng): (
        Application<'static, Pasta, R<13>, 4>,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StepRng,
    ),
) {
    black_box(
        app.seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(42u64),
        )
        .unwrap(),
    );
}

#[library_benchmark]
#[bench::fuse(setup = setup_fuse)]
fn fuse(
    (app, leaf1, leaf2, poseidon_params, mut rng): (
        Application<'static, Pasta, R<13>, 4>,
        Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
        Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StepRng,
    ),
) {
    let (proof, aux) = app
        .fuse(
            &mut rng,
            nontrivial::Hash2 { poseidon_params },
            (),
            leaf1,
            leaf2,
        )
        .unwrap();
    black_box(proof.carry::<nontrivial::InternalNode>(aux));
}

#[library_benchmark]
#[bench::verify_leaf(setup = setup_verify_leaf)]
fn verify_leaf(
    (app, leaf, mut rng): (
        Application<'static, Pasta, R<13>, 4>,
        Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
        StepRng,
    ),
) {
    assert!(black_box(app.verify(&leaf, &mut rng).unwrap()));
}

#[library_benchmark]
#[bench::verify_node(setup = setup_verify_node)]
fn verify_node(
    (app, node, mut rng): (
        Application<'static, Pasta, R<13>, 4>,
        Pcd<'static, Pasta, R<13>, nontrivial::InternalNode>,
        StepRng,
    ),
) {
    assert!(black_box(app.verify(&node, &mut rng).unwrap()));
}

#[library_benchmark]
#[bench::rerandomize(setup = setup_verify_node)]
fn rerandomize(
    (app, node, mut rng): (
        Application<'static, Pasta, R<13>, 4>,
        Pcd<'static, Pasta, R<13>, nontrivial::InternalNode>,
        StepRng,
    ),
) {
    black_box(1 + 1);
    black_box(app.rerandomize(node, &mut rng).unwrap());
}

library_benchmark_group!(
    name = pcd;
    benchmarks = application_build, seed, fuse, verify_leaf, verify_node, rerandomize
);

main!(library_benchmark_groups = pcd);
