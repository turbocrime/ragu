use alloc::vec::Vec;
use core::borrow::Borrow;

pub use ragu_arithmetic::poly_with_roots;
use ragu_arithmetic::{Cycle, ff::Field as _, poly_mul, rand::CryptoRng};
use ragu_circuits::polynomials::{ProductionRank, Rank, sparse};
use ragu_pasta::{Eq, EqAffine, Fp, Pasta};

/// Mirrors [`ragu_circuits::polynomials::sparse::Polynomial`], concrete over the
/// Pasta scalar field [`Fp`] and the [`ProductionRank`].
#[derive(Clone, Debug, Default)]
pub struct Polynomial(sparse::Polynomial<Fp, ProductionRank>);

impl Polynomial {
    /// The rank: coefficient capacity is `2^R`.
    pub const R: u32 = <ProductionRank as Rank>::RANK;

    /// Creates a new empty (zero) polynomial.
    #[must_use]
    pub fn new() -> Self {
        Self(sparse::Polynomial::new())
    }

    /// Compresses a dense coefficient vector into sparse form.
    ///
    /// Panics if `coeffs.len()` exceeds the capacity `2^R`.
    #[must_use]
    pub fn from_coeffs(coeffs: Vec<Fp>) -> Self {
        Self(sparse::Polynomial::from_coeffs(coeffs))
    }

    /// Creates a polynomial with random coefficients filling all slots.
    #[must_use]
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self(sparse::Polynomial::random(rng))
    }

    /// Iterates over the coefficients in ascending degree order, yielding
    /// [`Fp::ZERO`](ragu_arithmetic::ff::Field::ZERO) for gaps.
    pub fn iter_coeffs(&self) -> impl DoubleEndedIterator<Item = Fp> + ExactSizeIterator + '_ {
        self.0.iter_coeffs()
    }

    /// Multiplies all coefficients by `by`.
    pub fn scale(&mut self, by: Fp) {
        self.0.scale(by);
    }

    /// Adds the coefficients of `other` to `self`.
    pub fn add_assign(&mut self, other: &Self) {
        self.0.add_assign(&other.0);
    }

    /// Subtracts the coefficients of `other` from `self`.
    pub fn sub_assign(&mut self, other: &Self) {
        self.0.sub_assign(&other.0);
    }

    /// Negates all coefficients.
    pub fn negate(&mut self) {
        self.0.negate();
    }

    /// Horner-style weighted sum of polynomials by powers of `scale_factor`.
    #[must_use]
    pub fn fold<E: Borrow<Self>>(polys: impl IntoIterator<Item = E>, scale_factor: Fp) -> Self {
        polys.into_iter().fold(Self::new(), |mut acc, poly| {
            acc.scale(scale_factor);
            acc.add_assign(poly.borrow());
            acc
        })
    }

    /// Evaluates this polynomial at `z`.
    #[must_use]
    pub fn eval(&self, z: Fp) -> Fp {
        self.0.eval(z)
    }

    /// Transforms `p(X)` into `p(zX)`.
    pub fn dilate(&mut self, z: Fp) {
        self.0.dilate(z);
    }

    /// Inner product of `self` with the coefficient-reversed `other`.
    #[must_use]
    pub fn revdot(&self, other: &Self) -> Fp {
        self.0.revdot(&other.0)
    }

    /// Commits to this polynomial against the host generators, returning the
    /// Vesta point in projective form.
    #[must_use]
    pub fn commit(&self) -> Eq {
        self.0.commit(Pasta::host_generators(Pasta::baked()))
    }

    /// Commits to this polynomial against the host generators, returning the
    /// Vesta point normalized to affine.
    #[must_use]
    pub fn commit_to_affine(&self) -> EqAffine {
        self.0
            .commit_to_affine(Pasta::host_generators(Pasta::baked()))
    }
}

impl core::ops::AddAssign<&Self> for Polynomial {
    fn add_assign(&mut self, rhs: &Self) {
        Polynomial::add_assign(self, rhs);
    }
}

impl core::ops::SubAssign<&Self> for Polynomial {
    fn sub_assign(&mut self, rhs: &Self) {
        Polynomial::sub_assign(self, rhs);
    }
}

impl core::ops::Mul for Polynomial {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let a = self.0.iter_coeffs().collect::<Vec<_>>();
        let b = rhs.0.iter_coeffs().collect::<Vec<_>>();
        let mut out = Vec::new();
        poly_mul(&a, &b, &mut out);

        let out_len = out
            .iter()
            .rposition(|&x| x != Fp::ZERO)
            .map_or(0, |i| i + 1);
        out.truncate(out_len);

        Self::from_coeffs(out)
    }
}

impl ragu_arithmetic::Ring for Polynomial {
    type R = Self;
    type F = Fp;

    fn scale_assign(r: &mut Self, by: Fp) {
        r.scale(by);
    }
    fn add_assign(r: &mut Self, other: &Self) {
        Polynomial::add_assign(r, other);
    }
    fn sub_assign(r: &mut Self, other: &Self) {
        Polynomial::sub_assign(r, other);
    }
}
