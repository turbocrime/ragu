mod common;

use common::{setup_fuse, setup_seed, setup_verify_leaf, setup_verify_node};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::test_fixtures::nontrivial;
use std::hint::black_box;

fn bench_application_build_fn(c: &mut Criterion) {
    c.bench_function("pcd/poseidon/application_build", |b| {
        b.iter(|| {
            let pasta = Pasta::baked();
            black_box(nontrivial::build_app::<Pasta>(pasta));
        })
    });
}

fn bench_seed_fn(c: &mut Criterion) {
    c.bench_function("pcd/poseidon/seed", |b| {
        b.iter_batched(
            setup_seed,
            |(app, poseidon_params, mut rng)| {
                black_box(
                    app.seed(
                        &mut rng,
                        nontrivial::WitnessLeaf { poseidon_params },
                        Fp::from(42u64),
                    )
                    .unwrap(),
                );
            },
            BatchSize::LargeInput,
        )
    });
}

fn bench_fuse_fn(c: &mut Criterion) {
    c.bench_function("pcd/poseidon/fuse", |b| {
        b.iter_batched(
            setup_fuse,
            |(app, leaf1, leaf2, poseidon_params, mut rng)| {
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
            },
            BatchSize::LargeInput,
        )
    });
}

fn bench_verify_leaf_fn(c: &mut Criterion) {
    c.bench_function("pcd/poseidon/verify_leaf", |b| {
        b.iter_batched(
            setup_verify_leaf,
            |(app, leaf, mut rng)| {
                assert!(black_box(app.verify(&leaf, &mut rng).unwrap()));
            },
            BatchSize::LargeInput,
        )
    });
}

fn bench_verify_node_fn(c: &mut Criterion) {
    c.bench_function("pcd/poseidon/verify_node", |b| {
        b.iter_batched(
            setup_verify_node,
            |(app, node, mut rng)| {
                assert!(black_box(app.verify(&node, &mut rng).unwrap()));
            },
            BatchSize::LargeInput,
        )
    });
}

fn bench_rerandomize_fn(c: &mut Criterion) {
    c.bench_function("pcd/poseidon/rerandomize", |b| {
        b.iter_batched(
            setup_verify_node,
            |(app, node, mut rng)| {
                black_box(app.rerandomize(node, &mut rng).unwrap());
            },
            BatchSize::LargeInput,
        )
    });
}

criterion_group! {
    name = poseidon;
    config = Criterion::default();
    targets =
        bench_application_build_fn,
        bench_seed_fn,
        bench_fuse_fn,
        bench_verify_leaf_fn,
        bench_verify_node_fn,
        bench_rerandomize_fn,
}

criterion_main!(poseidon);
