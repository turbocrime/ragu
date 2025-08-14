use ff::Field;

use alloc::vec::Vec;

use crate::{
    CircuitObject,
    polynomials::{Rank, structured, unstructured},
};

/// Staging circuit polynomial for enforcing the correct structure of staging
/// witnesses.
#[derive(Clone)]
pub struct Staging<R: Rank> {
    start: usize,
    num: usize,
    _marker: core::marker::PhantomData<R>,
}

impl<R: Rank> Staging<R> {
    /// Creates a new staging circuit polynomial with the given `start` and
    /// `num` values. Witnesses that satisfy this circuit will have all
    /// non-`ONE` multiplication gate wires enforced to equal zero except
    /// between the `start..num` gates.
    pub fn new(start: usize, num: usize) -> Self {
        if start + num + 1 > R::n() {
            panic!(
                "start={start} + num={num} + 1 overflows the rank's n value {}",
                R::n()
            );
        }

        Self {
            start,
            num,
            _marker: core::marker::PhantomData,
        }
    }
}

impl<F: Field, R: Rank> CircuitObject<F, R> for Staging<R> {
    fn sxy(&self, x: F, y: F) -> F {
        assert!(self.start + self.num + 1 <= R::n());
        let reserved: usize = R::n() - self.start - self.num - 1;

        if x == F::ZERO || y == F::ZERO {
            // If either x or y is zero, the polynomial evaluates to zero.
            return F::ZERO;
        }

        let x_inv = x.invert().expect("x is not zero");
        let y2 = y.square();
        let y3 = y * y2;
        let x_y3 = x * y3;
        let xinv_y3 = x_inv * y3;

        let block = |end: usize, len: usize| -> F {
            let w = y * x.pow_vartime([(4 * R::n() - 2 - end) as u64]);
            let v = y2 * x.pow_vartime([(2 * R::n() + 1 + end) as u64]);
            let u = y3 * x.pow_vartime([(2 * R::n() - 2 - end) as u64]);

            let plus = arithmetic::geosum::<F>(x_y3, len);
            let minus = arithmetic::geosum::<F>(xinv_y3, len);

            w * plus + v * minus + u * plus
        };

        let c1 = block(self.start - 1, self.start);
        let c2 = block(R::n() - 2, reserved);

        y.pow_vartime([(3 * reserved) as u64]) * c1 + c2
    }

    fn sx(&self, x: F) -> unstructured::Polynomial<F, R> {
        assert!(self.start + self.num + 1 <= R::n());
        let reserved: usize = R::n() - self.start - self.num - 1;

        if x == F::ZERO {
            return unstructured::Polynomial::new();
        }

        let mut coeffs = Vec::with_capacity(R::num_coeffs());
        {
            let x_inv = x.invert().expect("x is not zero");
            let xn = x.pow_vartime([R::n() as u64]); // xn = x^n
            let xn2 = xn.square(); // xn2 = x^(2n)
            let mut u = xn2 * x_inv; // x^(2n - 1)
            let mut v = xn2; // x^(2n)
            let xn4 = xn2.square(); // x^(4n)
            let mut w = xn4 * x_inv; // x^(4n - 1)

            let mut alloc = || {
                let out = (u, v, w);
                u *= x_inv;
                v *= x;
                w *= x_inv;
                out
            };

            let mut enforce_zero = |out: (F, F, F)| {
                coeffs.push(out.0);
                coeffs.push(out.1);
                coeffs.push(out.2);
            };

            alloc(); // ONE

            for _ in 0..self.start {
                enforce_zero(alloc());
            }
            for _ in 0..self.num {
                alloc();
            }
            for _ in 0..reserved {
                enforce_zero(alloc());
            }
        }

        coeffs.push(F::ZERO); // The constant term is always zero.
        coeffs.reverse();

        unstructured::Polynomial::from_coeffs(coeffs)
    }

    fn sy(&self, y: F) -> structured::Polynomial<F, R> {
        assert!(self.start + self.num + 1 <= R::n());
        let reserved: usize = R::n() - self.start - self.num - 1;

        let mut poly = structured::Polynomial::new();
        if y == F::ZERO {
            return poly;
        }

        let mut yq = y.pow_vartime([(3 * (reserved + self.start)) as u64]);
        let y_inv = y.invert().expect("y is not zero");

        {
            let poly = poly.backward();

            // ONE
            poly.a.push(F::ZERO);
            poly.b.push(F::ZERO);
            poly.c.push(F::ZERO);

            for _ in 0..self.start {
                poly.a.push(yq);
                yq *= y_inv;
                poly.b.push(yq);
                yq *= y_inv;
                poly.c.push(yq);
                yq *= y_inv;
            }
            for _ in 0..self.num {
                poly.a.push(F::ZERO);
                poly.b.push(F::ZERO);
                poly.c.push(F::ZERO);
            }
            for _ in 0..reserved {
                poly.a.push(yq);
                yq *= y_inv;
                poly.b.push(yq);
                yq *= y_inv;
                poly.c.push(yq);
                yq *= y_inv;
            }
        }

        poly
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use proptest::prelude::*;
    use ragu_core::{
        Result,
        drivers::{Coeff, Driver, LinearExpression, Witness},
    };
    use ragu_pasta::Fp;
    use rand::thread_rng;

    use crate::{CircuitExt, CircuitObject, polynomials::Rank};

    impl<F: Field, R: Rank> crate::Circuit<F> for super::Staging<R> {
        type Instance<'source> = ();
        type Witness<'source> = ();
        type Output<'dr, D: Driver<'dr, F = F>> = ();
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
            &self,
            _: &mut D,
            _: Witness<D, Self::Instance<'source>>,
        ) -> Result<Self::Output<'dr, D>> {
            Ok(())
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
            &self,
            dr: &mut D,
            _: Witness<D, Self::Witness<'source>>,
        ) -> Result<(Self::Output<'dr, D>, Witness<D, Self::Aux<'source>>)>
        where
            Self: 'dr,
        {
            let reserved = self.start + self.num + 1;
            assert!(reserved <= R::n());

            for _ in 0..self.start {
                let (a, b, c) = dr.mul(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?;
                dr.enforce_zero(|lc| lc.add(&a))?;
                dr.enforce_zero(|lc| lc.add(&b))?;
                dr.enforce_zero(|lc| lc.add(&c))?;
            }

            for _ in 0..self.num {
                dr.mul(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?;
            }

            for _ in 0..(R::n() - reserved) {
                let (a, b, c) = dr.mul(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?;
                dr.enforce_zero(|lc| lc.add(&a))?;
                dr.enforce_zero(|lc| lc.add(&b))?;
                dr.enforce_zero(|lc| lc.add(&c))?;
            }

            Ok(((), D::just(|| ())))
        }
    }

    type R = crate::polynomials::R<7>;

    proptest! {
        #[test]
        fn test_exy_proptest(start in 0..R::n(), num in 0..R::n()) {
            prop_assume!(start + 1 + num <= R::n());

            let circuit = super::Staging::<R>::new(start, num);
            let circuitobj = circuit.clone().into_object::<R>().unwrap();

            let check = |x: Fp, y: Fp| {
                let xn_minus_1 = x.pow_vartime([(4 * R::n() - 1) as u64]);

                // This adjusts for the single "ONE" constraint which is always skipped
                // in staging witnesses.
                let sxy = circuitobj.sxy(x, y) - xn_minus_1;
                let mut sx = circuitobj.sx(x);
                {
                    sx[0] -= xn_minus_1;
                }
                let mut sy = circuitobj.sy(y);
                {
                    let sy = sy.backward();
                    sy.c[0] -= Fp::ONE;
                }

                prop_assert_eq!(sy.eval(x), sxy);
                prop_assert_eq!(sx.eval(y), sxy);
                prop_assert_eq!(circuit.sxy(x, y), sxy);
                prop_assert_eq!(circuit.sx(x).eval(y), sxy);
                prop_assert_eq!(circuit.sy(y).eval(x), sxy);

                Ok(())
            };

            let x = Fp::random(thread_rng());
            let y = Fp::random(thread_rng());
            check(x, y)?;
            check(Fp::ZERO, y)?;
            check(x, Fp::ZERO)?;
            check(Fp::ZERO, Fp::ZERO)?;

        }
    }
}
