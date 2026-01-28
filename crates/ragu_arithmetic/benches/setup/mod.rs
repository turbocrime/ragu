use ff::Field;
use pasta_curves::group::prime::PrimeCurveAffine;
use pasta_curves::{EpAffine, Fp, Fq};
use ragu_arithmetic::Domain;
use rand::SeedableRng;
use rand::rngs::SmallRng;

pub trait SetupRng<Out> {
    fn setup(self, rng: &mut SmallRng) -> Out;
}

impl<A, FA: FnOnce(&mut SmallRng) -> A> SetupRng<(A,)> for (FA,) {
    fn setup(self, rng: &mut SmallRng) -> (A,) {
        (self.0(rng),)
    }
}

impl<A, B, FA: FnOnce(&mut SmallRng) -> A, FB: FnOnce(&mut SmallRng) -> B> SetupRng<(A, B)>
    for (FA, FB)
{
    fn setup(self, rng: &mut SmallRng) -> (A, B) {
        (self.0(rng), self.1(rng))
    }
}

impl<
    A,
    B,
    C,
    FA: FnOnce(&mut SmallRng) -> A,
    FB: FnOnce(&mut SmallRng) -> B,
    FC: FnOnce(&mut SmallRng) -> C,
> SetupRng<(A, B, C)> for (FA, FB, FC)
{
    fn setup(self, rng: &mut SmallRng) -> (A, B, C) {
        (self.0(rng), self.1(rng), self.2(rng))
    }
}

pub fn mock_rng() -> SmallRng {
    SmallRng::seed_from_u64(0xBEEF_CAFE_DEAD_F00D)
}

pub fn setup_rng<Fns: SetupRng<T>, T>(fns: Fns) -> T {
    let mut rng = mock_rng();
    fns.setup(&mut rng)
}

pub fn setup_with_rng<T, Fns: SetupRng<S>, S>(other: T, fns: Fns) -> (T, S) {
    let mut rng = mock_rng();
    (other, fns.setup(&mut rng))
}

pub fn f<F: Field>(rng: &mut SmallRng) -> F {
    F::random(rng)
}

pub fn vec_f<const N: usize, F: Field>(rng: &mut SmallRng) -> Vec<F> {
    (0..N).map(|_| F::random(&mut *rng)).collect()
}

pub fn vec_affine<const N: usize>(rng: &mut SmallRng) -> Vec<EpAffine> {
    let g = EpAffine::generator();
    (0..N).map(|_| (g * Fq::random(&mut *rng)).into()).collect()
}

pub fn setup_domain_fft(k: u32) -> (Domain<Fp>, Vec<Fp>) {
    let mut rng = mock_rng();
    let domain = Domain::new(k);
    let data = (0..domain.n()).map(|_| Fp::random(&mut rng)).collect();
    (domain, data)
}

pub fn setup_domain_ell(k: u32) -> (Domain<Fp>, Fp, usize) {
    let mut rng = mock_rng();
    let domain = Domain::new(k);
    let n = domain.n();
    (domain, Fp::random(&mut rng), n)
}
