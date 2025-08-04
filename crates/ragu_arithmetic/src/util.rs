use ff::{Field, PrimeField};
use pasta_curves::{arithmetic::CurveAffine, group::Group};

use alloc::{vec, vec::Vec};

/// Evaluates a polynomial $p \in \mathbb{F}\[X]$ at a point $x \in \mathbb{F}$,
/// where $p$ is defined by `coeffs` in ascending order of degree.
pub fn eval<'a, F: Field, I: IntoIterator<Item = &'a F>>(coeffs: I, x: F) -> F
where
    I::IntoIter: DoubleEndedIterator,
{
    let mut result = F::ZERO;
    for coeff in coeffs.into_iter().rev() {
        result *= x;
        result += *coeff;
    }
    result
}

/// Computes $\langle \mathbf{a} , \mathbf{b} \rangle$ where $\mathbf{a}, \mathbf{b} \in \mathbb{F}^n$
/// are defined by the provided equal-length iterators.
///
/// # Panics
///
/// Panics if the lengths of $\mathbf{a}$ and $\mathbf{b}$ are not equal.
pub fn dot<'a, F: Field, I1: IntoIterator<Item = &'a F>, I2: IntoIterator<Item = &'a F>>(
    a: I1,
    b: I2,
) -> F
where
    I1::IntoIter: ExactSizeIterator,
    I2::IntoIter: ExactSizeIterator,
{
    let a = a.into_iter();
    let b = b.into_iter();
    assert_eq!(a.len(), b.len());
    a.into_iter()
        .zip(b)
        .map(|(a, b)| *a * *b)
        .fold(F::ZERO, |acc, x| acc + x)
}

/// Computes $a / (X - b)$ with no remainder for the given univariate polynomial $a \in \mathbb{F}\[X]$ and value $b \in \mathbb{F}$.
///
/// # Panics
///
/// Panics if the polynomial $a$ is of degree $0$, as it cannot be factored by a linear term.
pub fn factor<'a, F: Field, I: IntoIterator<Item = &'a F>>(a: I, mut b: F) -> Vec<F>
where
    I::IntoIter: DoubleEndedIterator + ExactSizeIterator,
{
    b = -b;
    let a = a.into_iter();

    if a.len() == 0 {
        panic!("cannot factor a polynomial of degree 0");
    }

    let mut q = vec![F::ZERO; a.len() - 1];

    let mut tmp = F::ZERO;
    for (q, r) in q.iter_mut().rev().zip(a.rev()) {
        let mut lead_coeff = *r;
        lead_coeff -= tmp;
        *q = lead_coeff;
        tmp = lead_coeff;
        tmp *= b;
    }

    q
}

/// Given a number of scalars, returns the ideal bucket size (in bits) for
/// multiexp, obtained through experimentation. This could probably be optimized
/// further and for particular compilation targets.
fn bucket_lookup(n: usize) -> usize {
    const LN_THRESHOLDS: [usize; 15] = [
        4, 4, 32, 55, 149, 404, 1097, 2981, 8104, 22027, 59875, 162755, 442414, 1202605, 3269018,
    ];

    let mut cur = 1;
    for &threshold in LN_THRESHOLDS.iter() {
        if n < threshold {
            return cur;
        }

        cur += 1;
    }
    cur
}

#[test]
fn test_bucket_lookup_thresholds() {
    for n in 0..8886111 {
        // This is heuristic behavior that uses floating point intrinsics to
        // succinctly estimate the correct bucket size for multiscalar
        // multiplication. These intrinsics are only available in the standard
        // library, so we replicate them (to sufficient extent) through a lookup
        // table.
        let expected = {
            if n < 4 {
                1
            } else if n < 32 {
                3
            } else {
                (f64::from(n as u32)).ln().ceil() as usize
            }
        };
        let actual = bucket_lookup(n);
        if expected != actual {
            panic!("n = {}: expected {}, got {}", n, expected, actual);
        }
    }
}

/// Compute the multiscalar multiplication $\langle \mathbf{a}, \mathbf{G} \rangle$ where
/// $\mathbf{a} \in \mathbb{F}^n$ is a vector of scalars and $\mathbf{G} \in \mathbb{G}^n$
/// is a vector of bases.
///
/// # Usage
///
/// Ensure that the provided iterators have the same length, or this function may not
/// behave properly or could even panic.
pub fn mul<
    'a,
    C: CurveAffine,
    A: IntoIterator<Item = &'a C::Scalar>,
    B: IntoIterator<Item = &'a C> + Clone,
>(
    coeffs: A,
    bases: B,
) -> C::Curve {
    let coeffs: Vec<_> = coeffs.into_iter().map(|a| a.to_repr()).collect();

    let c = bucket_lookup(coeffs.len());

    fn get_at<F: PrimeField>(segment: usize, c: usize, bytes: &F::Repr) -> usize {
        let skip_bits = segment * c;
        let skip_bytes = skip_bits / 8;

        if skip_bytes >= 32 {
            return 0;
        }

        let mut v = [0; 8];
        for (v, o) in v.iter_mut().zip(bytes.as_ref()[skip_bytes..].iter()) {
            *v = *o;
        }

        let mut tmp = u64::from_le_bytes(v);
        tmp >>= skip_bits - (skip_bytes * 8);
        tmp %= 1 << c;

        tmp as usize
    }

    let segments = (256 / c) + 1;

    let mut acc = C::Curve::identity();

    for current_segment in (0..segments).rev() {
        for _ in 0..c {
            acc = acc.double();
        }

        #[derive(Clone, Copy)]
        enum Bucket<C: CurveAffine> {
            None,
            Affine(C),
            Projective(C::Curve),
        }

        impl<C: CurveAffine> Bucket<C> {
            fn add_assign(&mut self, other: &C) {
                *self = match *self {
                    Bucket::None => Bucket::Affine(*other),
                    Bucket::Affine(a) => Bucket::Projective(a + *other),
                    Bucket::Projective(mut a) => {
                        a += *other;
                        Bucket::Projective(a)
                    }
                }
            }

            fn add(self, mut other: C::Curve) -> C::Curve {
                match self {
                    Bucket::None => other,
                    Bucket::Affine(a) => {
                        other += a;
                        other
                    }
                    Bucket::Projective(a) => other + a,
                }
            }
        }

        let mut buckets: Vec<Bucket<C>> = vec![Bucket::None; (1 << c) - 1];

        for (coeff, base) in coeffs.iter().zip(bases.clone().into_iter()) {
            let coeff = get_at::<C::Scalar>(current_segment, c, coeff);
            if coeff != 0 {
                buckets[coeff - 1].add_assign(base);
            }
        }

        // Summation by parts
        // e.g. 3a + 2b + 1c = a +
        //                    (a) + b +
        //                    ((a) + b) + c
        let mut running_sum = C::Curve::identity();
        for exp in buckets.into_iter().rev() {
            running_sum = exp.add(running_sum);
            acc += &running_sum;
        }
    }

    acc
}

#[test]
fn test_mul() {
    use pasta_curves::group::{Curve, prime::PrimeCurveAffine};

    let mut coeffs = vec![];
    for i in 0..1000 {
        coeffs.push(pasta_curves::Fp::from(i) * pasta_curves::Fp::MULTIPLICATIVE_GENERATOR);
    }

    let mut bases = vec![];
    for i in 0..1000 {
        bases.push((pasta_curves::EqAffine::generator() * pasta_curves::Fp::from(i)).to_affine());
    }

    let expected = coeffs
        .iter()
        .zip(bases.iter())
        .fold(pasta_curves::Eq::identity(), |acc, (scalar, point)| {
            acc + point * scalar
        });

    assert_eq!(mul(coeffs.iter(), bases.iter()), expected);
}

#[test]
fn test_dot() {
    use pasta_curves::Fp as F;

    let powers = vec![
        F::ONE,
        F::DELTA,
        F::DELTA.square(),
        F::DELTA.square() * F::DELTA,
        F::DELTA.square().square(),
    ];
    let coeffs = vec![F::from(1), F::from(2), F::from(3), F::from(4), F::from(5)];

    assert_eq!(
        dot(powers.iter(), coeffs.iter().rev().rev()),
        eval(coeffs.iter(), F::DELTA)
    );
}

#[test]
fn test_factor() {
    use pasta_curves::Fp as F;

    let poly = vec![
        F::DELTA,
        F::DELTA.square(),
        F::from(348) * F::DELTA,
        F::from(438) * F::MULTIPLICATIVE_GENERATOR,
    ];
    let x = F::from(F::TWO_INV);
    let v = eval(poly.iter(), x);
    let quot = factor(poly.iter(), x);
    let y = F::from(F::DELTA + F::from(100));
    assert_eq!(eval(quot.iter(), y) * (y - x), eval(poly.iter(), y) - v);
}
