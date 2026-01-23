use arithmetic::Cycle;
use ragu_circuits::polynomials::R;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::test_fixtures::nontrivial;
use ragu_pcd::{Application, Pcd};
use rand::rngs::mock::StepRng;

pub fn mock_rng() -> StepRng {
    StepRng::new(u64::from_le_bytes(*b"innocent"), 0xF2EE_CAFE_BABE_2DA7)
}

pub fn setup_seed() -> (
    Application<'static, Pasta, R<13>, 4>,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StepRng,
) {
    let pasta = Pasta::baked();
    (
        nontrivial::build_app::<Pasta>(pasta),
        Pasta::circuit_poseidon(pasta),
        mock_rng(),
    )
}

pub fn setup_fuse() -> (
    Application<'static, Pasta, R<13>, 4>,
    Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
    Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StepRng,
) {
    let pasta = Pasta::baked();
    let app = nontrivial::build_app::<Pasta>(pasta);
    let mut rng = mock_rng();

    let (proof1, aux1) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf {
                poseidon_params: Pasta::circuit_poseidon(pasta),
            },
            Fp::from(1u64),
        )
        .unwrap();
    let leaf1 = proof1.carry::<nontrivial::LeafNode>(aux1);

    let (proof2, aux2) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf {
                poseidon_params: Pasta::circuit_poseidon(pasta),
            },
            Fp::from(2u64),
        )
        .unwrap();
    let leaf2 = proof2.carry::<nontrivial::LeafNode>(aux2);

    (
        app,
        leaf1,
        leaf2,
        Pasta::circuit_poseidon(pasta),
        mock_rng(),
    )
}

pub fn setup_verify_leaf() -> (
    Application<'static, Pasta, R<13>, 4>,
    Pcd<'static, Pasta, R<13>, nontrivial::LeafNode>,
    StepRng,
) {
    let pasta = Pasta::baked();
    let app = nontrivial::build_app::<Pasta>(pasta);
    let mut rng = mock_rng();

    let (proof, aux) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf {
                poseidon_params: Pasta::circuit_poseidon(pasta),
            },
            Fp::from(1u64),
        )
        .unwrap();
    let leaf = proof.carry::<nontrivial::LeafNode>(aux);

    (app, leaf, mock_rng())
}

pub fn setup_verify_node() -> (
    Application<'static, Pasta, R<13>, 4>,
    Pcd<'static, Pasta, R<13>, nontrivial::InternalNode>,
    StepRng,
) {
    let pasta = Pasta::baked();
    let app = nontrivial::build_app::<Pasta>(pasta);
    let mut rng = mock_rng();

    let (proof1, aux1) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf {
                poseidon_params: Pasta::circuit_poseidon(pasta),
            },
            Fp::from(1u64),
        )
        .unwrap();
    let leaf1 = proof1.carry::<nontrivial::LeafNode>(aux1);

    let (proof2, aux2) = app
        .seed(
            &mut rng,
            nontrivial::WitnessLeaf {
                poseidon_params: Pasta::circuit_poseidon(pasta),
            },
            Fp::from(2u64),
        )
        .unwrap();
    let leaf2 = proof2.carry::<nontrivial::LeafNode>(aux2);

    let (proof, aux) = app
        .fuse(
            &mut rng,
            nontrivial::Hash2 {
                poseidon_params: Pasta::circuit_poseidon(pasta),
            },
            (),
            leaf1,
            leaf2,
        )
        .unwrap();
    let node = proof.carry::<nontrivial::InternalNode>(aux);

    (app, node, mock_rng())
}
