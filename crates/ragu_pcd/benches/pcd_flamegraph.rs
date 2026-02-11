//! Complete PCD flow benchmark with flamegraph generation.
//!
//! Measures the full post-build pipeline: seed → seed → fuse → rerandomize.
//! Flamegraphs (regular + differential when baseline exists) are written as
//! SVG files alongside the callgrind output in `target/gungraun/`.

#![allow(clippy::type_complexity)]

mod setup;

use gungraun::{
    Callgrind, FlamegraphConfig, LibraryBenchmarkConfig, library_benchmark,
    library_benchmark_group, main,
};
use ragu_pasta::Fp;
use ragu_pcd::test_fixtures::nontrivial;
use ragu_pcd::Application;
use rand::rngs::StdRng;
use setup::setup_seed;
use std::hint::black_box;

use arithmetic::Cycle;
use ragu_circuits::polynomials::R;
use ragu_pasta::Pasta;

#[library_benchmark(setup = setup_seed)]
#[bench::complete()]
fn complete_flow(
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
    name = pcd_flow;
    benchmarks = complete_flow
);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(
            Callgrind::default()
                .flamegraph(FlamegraphConfig::default())
        );
    library_benchmark_groups = pcd_flow
);
