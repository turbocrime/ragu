//! Provides [`SlotVec`], a wrapper around [`Vec<T>`] whose length is a
//! circuit-construction parameter rather than a compile-time constant.
//!
//! [`FixedVec`](ragu_primitives::vec::FixedVec) carries its length in a
//! [`Len`](ragu_primitives::vec::Len) type so that every instance of a given
//! Rust type has the same wire count. That is the right shape when the length
//! is a property of the *type*. In this crate the wire-group lengths are
//! properties of the *application*: they come from the capacity settled during
//! registration, which differs between applications without differing at Rust
//! compile time.
//!
//! [`SlotVec`] implements [`Gadget`] for that case. The length discipline is:
//!
//! * The length is always a circuit-construction parameter — it comes from the
//!   capacity that configured the circuit being synthesized, never from witness
//!   data.
//! * Two `SlotVec`s meet in a correspondence (equality enforcement, wire
//!   mapping) only when both were built at that same capacity, so their
//!   lengths agree by construction — and the element-wise operations below
//!   *check* that rather than assume it, because they `zip`, and a `zip` over
//!   a mismatch would enforce equality on a prefix and report success.
//! * Fungibility — every instance of a gadget type having the same wire
//!   count — is an API contract of the broader gadget ecosystem, not a
//!   safety invariant of [`GadgetKind`] (see that trait's safety
//!   documentation: the sole safety obligation is `Send` propagation).
//!   `SlotVec` is deliberately not fungible as a Rust type; it is fungible
//!   *per capacity*, which is the granularity at which this crate's circuits
//!   are constructed and registered.

use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use ragu_arithmetic::ff::Field;
use ragu_core::{
    Error, Result,
    convert::WireMap,
    drivers::Driver,
    gadgets::{Bound, Gadget, GadgetKind, WireEqualizer},
};
use ragu_primitives::{
    comparison::GadgetEquals,
    consistent::Consistent,
    io::{Buffer, Write},
};

/// A vector gadget whose length is a circuit-construction parameter.
///
/// See the [module documentation](self) for the length discipline. Construct
/// with [`SlotVec::with_len`], which checks a length taken from a plan against
/// data that crossed an API boundary.
pub(crate) struct SlotVec<T> {
    v: Vec<T>,
}

impl<T> SlotVec<T> {
    /// Wraps a vector, checking its length against `expected` (a plan value).
    pub(crate) fn with_len(v: Vec<T>, expected: usize) -> Result<Self> {
        if v.len() != expected {
            return Err(Error::VectorLengthMismatch {
                expected,
                actual: v.len(),
            });
        }
        Ok(SlotVec { v })
    }
}

impl<T: Clone> Clone for SlotVec<T> {
    fn clone(&self) -> Self {
        SlotVec { v: self.v.clone() }
    }
}

impl<T> Deref for SlotVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.v
    }
}

impl<T> DerefMut for SlotVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.v
    }
}

impl<T> IntoIterator for SlotVec<T> {
    type Item = T;
    type IntoIter = alloc::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.v.into_iter()
    }
}

impl<T> FromIterator<T> for SlotVec<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        SlotVec {
            v: iter.into_iter().collect(),
        }
    }
}

impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Gadget<'dr, D> for SlotVec<G> {
    type Kind = SlotVec<PhantomData<G::Kind>>;
}

impl<F: Field, G: Write<F>> Write<F> for SlotVec<PhantomData<G>> {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &SlotVec<Bound<'dr, D, G>>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        for item in &this.v {
            G::write_gadget(item, dr, buf)?;
        }
        Ok(())
    }
}

/// Rejects two `SlotVec`s of different lengths meeting in a correspondence.
///
/// The pairwise walks below `zip`, which stops at the shorter side — so a
/// mismatch would enforce equality on a prefix and report success. Lengths
/// agree by construction (both sides come from the same settled capacity), so
/// this can only fire on a construction bug; it is an error rather than a
/// `debug_assert` because a release build silently checking fewer wires than
/// it claims to is not a failure mode this crate can afford.
fn same_len(a: usize, b: usize) -> Result<()> {
    if a != b {
        return Err(Error::VectorLengthMismatch {
            expected: a,
            actual: b,
        });
    }
    Ok(())
}

impl<F: Field, G: GadgetEquals<F>> GadgetEquals<F> for SlotVec<PhantomData<G>> {
    fn enforce_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        dr: &mut D1,
        a: &Bound<'dr, D2, Self>,
        b: &Bound<'dr, D2, Self>,
    ) -> Result<()> {
        same_len(a.len(), b.len())?;
        for (a, b) in a.iter().zip(b.iter()) {
            G::enforce_equal_gadget(dr, a, b)?;
        }
        Ok(())
    }
}

impl<'dr, D: Driver<'dr>, G: Consistent<'dr, D>> Consistent<'dr, D> for SlotVec<G> {
    fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
        for item in self.iter() {
            item.enforce_consistent(dr)?;
        }
        Ok(())
    }
}

/// Safety: `G: GadgetKind<F>` implies that `Bound<'dr, D, G>` is `Send` when
/// `D::Wire` is `Send`, by the safety contract of `GadgetKind`. Because
/// `SlotVec<Bound<'dr, D, G>>` only contains `Bound<'dr, D, G>` values, it is
/// also `Send` when `D::Wire` is `Send`. That `Send` propagation is the
/// trait's sole safety invariant; fungibility is a separate API contract,
/// addressed by the length discipline in the [module documentation](self).
unsafe impl<F: Field, G: GadgetKind<F>> GadgetKind<F> for SlotVec<PhantomData<G>> {
    type Rebind<'dr, D: Driver<'dr, F = F>> = SlotVec<Bound<'dr, D, G>>;

    fn map_gadget<'src, 'dst, WM: WireMap<F>>(
        this: &Bound<'src, WM::Src, Self>,
        wm: &mut WM,
    ) -> Result<Bound<'dst, WM::Dst, Self>>
    where
        WM::Src: Driver<'src, F = F>,
        WM::Dst: Driver<'dst, F = F>,
    {
        this.iter().map(|g| G::map_gadget(g, wm)).collect()
    }

    fn enforce_conservative_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        eq: &mut WireEqualizer<'_, 'dr, D1>,
        a: &Bound<'dr, D2, Self>,
        b: &Bound<'dr, D2, Self>,
    ) -> Result<()> {
        same_len(a.len(), b.len())?;
        for (a, b) in a.iter().zip(b.iter()) {
            G::enforce_conservative_equal_gadget(eq, a, b)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn with_len_rejects_mismatch() {
        let result = SlotVec::with_len(vec![1, 2], 3);
        match result {
            Err(Error::VectorLengthMismatch { expected, actual }) => {
                assert_eq!(expected, 3);
                assert_eq!(actual, 2);
            }
            Err(_) => panic!("expected VectorLengthMismatch"),
            Ok(_) => panic!("expected error"),
        }
    }
}
