#![allow(clippy::type_complexity)]

mod setup;

use arithmetic::Cycle;
use gungraun::{
    Callgrind, FlamegraphConfig, LibraryBenchmarkConfig, library_benchmark,
    library_benchmark_group, main,
};
use ragu_circuits::polynomials::R;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::test_fixtures::nontrivial;
use ragu_pcd::{Application, ApplicationBuilder};
use rand::rngs::StdRng;
use setup::{setup_finalize, setup_register, setup_seed};
use std::hint::black_box;

#[library_benchmark(setup = setup_register)]
#[bench::register()]
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

#[library_benchmark(setup = setup_finalize)]
#[bench::finalize()]
fn finalize(
    (app, pasta): (
        ApplicationBuilder<'static, Pasta, R<13>, 4>,
        &'static <Pasta as Cycle>::Params,
    ),
) {
    black_box(app.finalize(pasta)).unwrap();
}

library_benchmark_group!(
    name = app_setup;
    benchmarks = register, finalize
);

#[library_benchmark(setup = setup_seed)]
#[bench::pcd_flamegraph()]
fn pcd_flamegraph(
    (app, poseidon_params, mut rng): (
        Application<'static, Pasta, R<13>, 4>,
        &'static <Pasta as Cycle>::CircuitPoseidon,
        StdRng,
    ),
) {
    black_box({
        // seed two leaf proofs
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

        // fuse into an internal node
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

        // rerandomize the fused proof
        app.rerandomize(node, &mut rng).unwrap()
    });
}

library_benchmark_group!(
    name = app_flamegraphs;
    benchmarks = pcd_flamegraph
);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(
            Callgrind::default()
                .flamegraph(FlamegraphConfig::default())
        );
    library_benchmark_groups = app_setup, app_flamegraphs
);
