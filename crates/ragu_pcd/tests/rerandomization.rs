use ragu_circuits::polynomials::R;
use ragu_pasta::Pasta;
use ragu_pcd::ApplicationBuilder;
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn rerandomization_flow() {
    use ragu_pcd::test_fixtures::trivial;

    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(trivial::Step0)
        .unwrap()
        .register(trivial::Step1)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let mut rng = StdRng::seed_from_u64(1234);

    let seeded = app.seed(&mut rng, trivial::Step0, ()).unwrap().0;
    let seeded = seeded.carry::<trivial::HeaderA>(());
    assert!(app.verify(&seeded, &mut rng).unwrap());

    // Rerandomize
    let seeded = app.rerandomize(seeded, &mut rng).unwrap();
    assert!(app.verify(&seeded, &mut rng).unwrap());

    let fused = app
        .fuse(&mut rng, trivial::Step1, (), seeded.clone(), seeded)
        .unwrap()
        .0;
    let fused = fused.carry::<trivial::HeaderA>(());
    assert!(app.verify(&fused, &mut rng).unwrap());

    let fused = app.rerandomize(fused, &mut rng).unwrap();
    assert!(app.verify(&fused, &mut rng).unwrap());
}
