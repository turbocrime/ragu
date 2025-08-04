//! Implements logic for endoscaling, as introduced in
//! [Halo](https://eprint.iacr.org/2019/1021).
//!
//! An endoscalar is the catchy name for a small binary string that is used to
//! perform elliptic curve scalar multiplication on curves that have an
//! efficient endomorphism attached. By producing endoscalars as challenges and
//! applying an appropriate algorithm, points on an elliptic curve can be
//! multiplied by equally "random" challenge scalars more efficiently within a
//! circuit than an arbitrary scalar.
//!
//! This module provides an implementation of the scaling operation for curves
//! which support the endomorphism, and an implementation of the algorithm for
//! recovering the effective scalar that an endoscalar maps to for a particular
//! prime field.

use arithmetic::CurveAffine;
use ff::{Field, PrimeField, WithSmallOrderMulGroup};
use ragu_core::{
    Result,
    drivers::{Coeff, Driver, LinearExpression, Witness},
    gadgets::Gadget,
    maybe::Maybe,
};

use alloc::vec::Vec;

use crate::{
    Boolean, Element, Point,
    demoted::Demoted,
    fixedvec::{ConstLen, FixedVec},
};

/// Represents a $128$-bit challenge used to scale elliptic curve points.
#[derive(Gadget)]
pub struct Endoscalar<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    bits: FixedVec<Demoted<'dr, D, Boolean<'dr, D>>, ConstLen<128>>,
    #[ragu(witness)]
    value: Witness<D, u128>,
}

impl<'dr, D: Driver<'dr>> Endoscalar<'dr, D> {
    /// Allocate an endoscalar with the provided `u128` value.
    pub fn alloc(dr: &mut D, value: Witness<D, u128>) -> Result<Self> {
        // Convert the provided u128 into a little-endian representation of its
        // bits.
        let mut bits = Vec::with_capacity(128);
        for i in 0..128 {
            let bit = Boolean::alloc(dr, value.view().map(|v| (v >> i) & 1 == 1))?;
            bits.push(Demoted::new(&bit));
        }

        Ok(Endoscalar {
            bits: FixedVec::try_from(bits).expect("correct length"),
            value,
        })
    }

    /// Returns an iterator over the bits in this endoscalar, little endian order.
    pub fn bits(&self) -> impl Iterator<Item = Boolean<'dr, D>> {
        let mut bits = self
            .value
            .view()
            .map(|v| (0..128).map(move |i| (v >> i) & 1 == 1));

        self.bits.iter().map(move |demoted_bit| {
            demoted_bit.promote(bits.view_mut().map(|bits| bits.next().unwrap()))
        })
    }

    /// Extracts an endoscalar from a random element in the field.
    pub fn extract(dr: &mut D, elem: Element<'dr, D>) -> Result<Self>
    where
        D::F: WithSmallOrderMulGroup<3>,
    {
        let mut bits = Vec::with_capacity(128);
        let mut value = D::just(|| 0u128);
        let mut constant = D::F::ZERO;

        let mut coeff_0 = D::F::ZERO;
        let mut coeff_1 = D::F::ZERO;
        let coeff_2 = D::F::MULTIPLICATIVE_GENERATOR;
        let coeff_3 = D::F::ONE - D::F::MULTIPLICATIVE_GENERATOR;

        for i in 0..128 {
            let (sqrt, bit) = D::with(|| {
                let value = *elem.value().take() + constant;

                if let Some(sqrt) = value.sqrt().into_option() {
                    Ok((sqrt, true))
                } else {
                    let sqrt = (value * D::F::MULTIPLICATIVE_GENERATOR)
                        .sqrt()
                        .into_option()
                        .expect("should produce a square if the other didn't");
                    Ok((sqrt, false))
                }
            })?
            .cast();

            value.view_mut().map(|v| {
                if *bit.snag() {
                    *v |= 1 << i
                }
            });

            let bit = Boolean::alloc(dr, bit)?;
            let (_, square) = Element::alloc_square(dr, sqrt)?;
            let vb = elem.mul(dr, &bit.element())?;

            // Enforce that the square is equal to
            //     (elem + i) if bit == 1
            //     (elem + i) * MULTIPLICATIVE_GENERATOR) if bit == 0
            // This is done by enforcing the linear constraint:
            //
            //     square = bit * (elem + i)
            //            + (1 - bit) * ((elem + i) * MULTIPLICATIVE_GENERATOR)
            //
            //            = i * MULTIPLICATIVE_GENERATOR
            //            + bit * (i * (1 - MULTIPLICATIVE_GENERATOR))
            //            + elem * MULTIPLICATIVE_GENERATOR
            //            + vb * (1 - MULTIPLICATIVE_GENERATOR)
            dr.enforce_zero(|lc| {
                lc.add_term(&D::ONE, coeff_0.into())
                    .add_term(bit.wire(), coeff_1.into())
                    .add_term(elem.wire(), coeff_2.into())
                    .add_term(vb.wire(), coeff_3.into())
                    .sub(square.wire())
            })?;

            bits.push(Demoted::new(&bit));
            constant += D::F::ONE;
            coeff_0 += coeff_2;
            coeff_1 += coeff_3;
        }

        Ok(Endoscalar {
            bits: FixedVec::try_from(bits).expect("correct length"),
            value,
        })
    }

    /// Scale a point by the endoscalar.
    pub fn group_scale<C: CurveAffine<Base = D::F>>(
        &self,
        dr: &mut D,
        p: &Point<'dr, D, C>,
    ) -> Result<Point<'dr, D, C>> {
        let mut acc = p.endo(dr)?.add_incomplete(dr, p)?.double(dr)?;
        let mut bits = self.bits();

        for _ in 0..64 {
            let negate_bit = bits.next().unwrap();
            let endo_bit = bits.next().unwrap();

            let q = p
                .conditional_negate(dr, &negate_bit)?
                .conditional_endo(dr, &endo_bit)?;
            acc = acc.double_and_add_incomplete(dr, &q)?;
        }

        Ok(acc)
    }

    /// Scale $1$ by the endoscalar.
    pub fn field_scale(&self, dr: &mut D) -> Result<Element<'dr, D>>
    where
        D::F: WithSmallOrderMulGroup<3>,
    {
        let mut constant_term = (D::F::ZETA + D::F::ONE).double();
        let coeffs = [
            -D::F::from(2),
            D::F::ZETA - D::F::ONE,
            (D::F::ONE - D::F::ZETA).double(),
        ];

        let mut acc = Element::zero(dr);
        let mut bits = self.bits();

        for _ in 0..64 {
            let n = bits.next().unwrap();
            let e = bits.next().unwrap();
            let ne = n.and(dr, &e)?;

            acc = acc.double(dr);
            constant_term = constant_term.double();
            constant_term += D::F::ONE;

            let n = n.element().scale(dr, Coeff::Arbitrary(coeffs[0]));
            let e = e.element().scale(dr, Coeff::Arbitrary(coeffs[1]));
            let ne = ne.element().scale(dr, Coeff::Arbitrary(coeffs[2]));

            acc = acc.add(dr, &n);
            acc = acc.add(dr, &e);
            acc = acc.add(dr, &ne);
        }

        let tmp = Element::constant(dr, constant_term);
        acc = acc.add(dr, &tmp);

        Ok(acc)
    }
}

#[cfg(test)]
mod tests {
    use super::{Element, Endoscalar, Maybe, Point};
    use arithmetic::{CurveAffine, CurveExt};
    use ff::{Field, PrimeField, WithSmallOrderMulGroup};
    use group::{Group, prime::PrimeCurveAffine};
    use ragu::{Result, drivers::Simulator};
    use ragu_pasta::{EpAffine, Fp};
    use rand::{Rng, thread_rng};

    pub struct EndoscalarTest {
        pub value: u128,
    }

    impl EndoscalarTest {
        /// Implements [Algorithm 1, \[BGH19\]](https://eprint.iacr.org/2019/1021).
        pub fn scale<C: CurveAffine>(&self, p: &C) -> C {
            let p = p.to_curve();
            let mut acc = (p.endo() + p).double();
            for bits in (0..64).map(|i| self.value >> (i << 1)) {
                let mut s = p;
                if bits & 0b01 != 0 {
                    s = -s;
                }
                if bits & 0b10 != 0 {
                    s = s.endo();
                }

                acc = (acc + s) + acc;
            }
            acc.into()
        }

        /// Implements [Algorithm 2, \[BGH19\]](https://eprint.iacr.org/2019/1021).
        pub fn compute_scalar<F: WithSmallOrderMulGroup<3>>(&self) -> F {
            let mut acc = (F::ZETA + F::ONE).double();
            for bits in (0..64).map(|i| self.value >> (i << 1)) {
                let mut tmp = F::ONE;
                if bits & 0b01 != 0 {
                    tmp = -tmp;
                }
                if bits & 0b10 != 0 {
                    tmp = tmp * F::ZETA;
                }
                acc = acc.double() + tmp;
            }
            acc
        }
    }

    pub fn extract_endoscalar<F: PrimeField>(value: F) -> EndoscalarTest {
        // Given a random output of a secure algebraic hash function, we can extract
        // 128 bits of "randomness" from the value without having to perform a
        // complete decomposition. Instead, we'll witness 128 bits where each bit
        // represents whether or not the value added to a fixed constant is a
        // quadratic residue. This can be tested easily in the circuit.

        let mut endoscalar = 0u128;

        for i in (0..128).rev() {
            endoscalar <<= 1;
            if (value + F::from(i as u64)).sqrt().into_option().is_some() {
                endoscalar |= 1;
            }
        }

        EndoscalarTest { value: endoscalar }
    }

    #[test]
    fn test_endoscaling_consistency() {
        use group::prime::PrimeCurveAffine;
        use ragu_pasta::{EpAffine, Fq};

        let p = EpAffine::generator();
        let e = EndoscalarTest {
            value: 206786806484900909362154774549736492353,
        };
        let scaled = e.scale(&p);
        let expected: EpAffine = (p * e.compute_scalar::<Fq>()).into();

        assert_eq!(scaled, expected);
    }

    #[test]
    fn test_extract() -> Result<()> {
        let p = EpAffine::generator();
        let r = Fp::random(thread_rng());
        let extracted = extract_endoscalar(r).value;

        Simulator::<Fp>::simulate((r, extracted, p), |dr, witness| {
            let (r, extracted, p) = witness.cast();
            let p = Point::alloc(dr, p)?;
            let r = Element::alloc(dr, r)?;
            let my_extracted = Endoscalar::extract(dr, r)?;
            let allocated = Endoscalar::alloc(dr, extracted)?;

            assert_eq!(my_extracted.value.snag(), allocated.value.snag());

            let a = my_extracted.group_scale(dr, &p)?;
            let b = allocated.group_scale(dr, &p)?;
            assert_eq!(a.value().take(), b.value().take());

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_endoscaling() -> Result<()> {
        let p = EpAffine::generator();
        let r: u128 = thread_rng().r#gen();
        let expected = EndoscalarTest { value: r }.scale(&p);

        Simulator::simulate((p, r), |dr, witness| {
            let (p, r) = witness.cast();
            let p = Point::alloc(dr, p.clone())?;
            let r = Endoscalar::alloc(dr, r.clone())?;

            assert_eq!(r.group_scale(dr, &p)?.value().take(), expected);

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_endopacking() -> Result<()> {
        let r: u128 = thread_rng().r#gen();
        let expected: Fp = EndoscalarTest { value: r }.compute_scalar();

        Simulator::<Fp>::simulate(r, |dr, witness| {
            let r = Endoscalar::alloc(dr, witness)?;
            let s = r.field_scale(dr)?;

            assert_eq!(*s.value().take(), expected);

            Ok(())
        })?;

        Ok(())
    }
}
