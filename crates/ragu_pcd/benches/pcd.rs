#![allow(clippy::type_complexity)]

use arithmetic::Cycle;
use gungraun::{library_benchmark, library_benchmark_group, main};
use ragu_circuits::polynomials::R;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::test_fixtures::nontrivial;
use ragu_pcd::{Application, ApplicationBuilder, Pcd};
use rand::SeedableRng;
use rand::rngs::SmallRng;
use std::hint::black_box;

fn mock_rng() -> SmallRng {
    SmallRng::seed_from_u64(0xF2EE_CAFE_BABE_2DA7)
}

fn setup_register() -> (
    nontrivial::WitnessLeaf<'static, Pasta>,
    nontrivial::Hash2<'static, Pasta>,
) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    (
        nontrivial::WitnessLeaf { poseidon_params },
        nontrivial::Hash2 { poseidon_params },
    )
}

fn setup_finalize() -> (
    ragu_pcd::ApplicationBuilder<'static, Pasta, R<13>, 4>,
    &'static <Pasta as Cycle>::Params,
) {
    let pasta = Pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap()
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap();
    (app, pasta)
}

fn setup_seed() -> (
    Application<'static, Pasta, R<13>, 4>,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    SmallRng,
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
    SmallRng,
) {
    let (app, poseidon_params, mut rng) = setup_seed();

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

    (app, leaf1, leaf2, poseidon_params, rng)
}

fn setup_verify_leaf() -> (
    Application<'static, Pasta, R<13>, 4>,
    Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
    SmallRng,
) {
    let (app, poseidon_params, mut rng) = setup_seed();

    let (proof, aux) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(1u64),
        )
        .unwrap();
    let leaf = proof.carry::<nontrivial::LeafNode>(aux);

    (app, leaf, rng)
}

fn setup_verify_node() -> (
    Application<'static, Pasta, R<13>, 4>,
    Pcd<'static, Pasta, R<13>, nontrivial::InternalNode>,
    SmallRng,
) {
    let (app, poseidon_params, mut rng) = setup_seed();

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

    (app, node, rng)
}

#[library_benchmark]
#[bench::register(setup = setup_register)]
fn register(
    (leaf, hash): (
        nontrivial::WitnessLeaf<'static, Pasta>,
        nontrivial::Hash2<'static, Pasta>,
    ),
) {
    black_box(
        ApplicationBuilder::<Pasta, R<13>, 4>::new()
            .register(leaf)
            .unwrap()
            .register(hash)
            .unwrap(),
    );
}

#[library_benchmark]
#[bench::finalize(setup = setup_finalize)]
fn finalize(
    (app, pasta): (
        ragu_pcd::ApplicationBuilder<'static, Pasta, R<13>, 4>,
        &'static <Pasta as Cycle>::Params,
    ),
) {
    black_box(app.finalize(pasta)).unwrap();
}

library_benchmark_group!(
    name = app_setup;
    benchmarks = register, finalize
);

#[library_benchmark]
#[bench::seed(setup = setup_seed)]
fn seed(
    (app, poseidon_params, mut rng): (
        Application<'static, Pasta, R<13>, 4>,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        SmallRng,
    ),
) {
    black_box(app.seed(
        &mut rng,
        nontrivial::WitnessLeaf { poseidon_params },
        Fp::from(42u64),
    ))
    .unwrap();
}

#[library_benchmark]
#[bench::fuse(setup = setup_fuse)]
fn fuse(
    (app, leaf1, leaf2, poseidon_params, mut rng): (
        Application<'static, Pasta, R<13>, 4>,
        Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
        Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        SmallRng,
    ),
) {
    black_box(app.fuse(
        &mut rng,
        nontrivial::Hash2 { poseidon_params },
        (),
        leaf1,
        leaf2,
    ))
    .unwrap();
}

library_benchmark_group!(
    name = app_proof;
    benchmarks = seed, fuse
);

#[library_benchmark]
#[bench::leaf(setup = setup_verify_leaf)]
fn verify_leaf(
    (app, leaf, mut rng): (
        Application<'static, Pasta, R<13>, 4>,
        Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
        SmallRng,
    ),
) {
    black_box(app.verify(&leaf, &mut rng)).unwrap();
}

#[library_benchmark]
#[bench::node(setup = setup_verify_node)]
fn verify_node(
    (app, node, mut rng): (
        Application<'static, Pasta, R<13>, 4>,
        Pcd<'static, Pasta, R<13>, nontrivial::InternalNode>,
        SmallRng,
    ),
) {
    black_box(app.verify(&node, &mut rng)).unwrap();
}

#[library_benchmark]
#[bench::rerandomize(setup = setup_verify_node)]
fn rerandomize(
    (app, node, mut rng): (
        Application<'static, Pasta, R<13>, 4>,
        Pcd<'static, Pasta, R<13>, nontrivial::InternalNode>,
        SmallRng,
    ),
) {
    black_box(app.rerandomize(node, &mut rng)).unwrap();
}

library_benchmark_group!(
    name = app_verify;
    benchmarks = verify_leaf, verify_node, rerandomize
);

main!(library_benchmark_groups = app_setup, app_proof, app_verify);
