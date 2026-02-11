use arithmetic::Cycle;
use ragu_circuits::polynomials::R;
use ragu_pasta::Pasta;
use ragu_pcd::test_fixtures::nontrivial;
use ragu_pcd::{Application, ApplicationBuilder};
use rand::SeedableRng;
use rand::rngs::StdRng;

pub fn setup_register() -> (
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

pub fn setup_finalize() -> (
    ApplicationBuilder<'static, Pasta, R<13>, 4>,
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

pub fn setup_seed() -> (
    Application<'static, Pasta, R<13>, 4>,
    &'static <Pasta as Cycle>::CircuitPoseidon,
    StdRng,
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
    (app, poseidon_params, StdRng::seed_from_u64(1234))
}
