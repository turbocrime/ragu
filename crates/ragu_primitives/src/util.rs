//! This is an internal module used to store helper utilities that are not part
//! of the public API (yet).

use ff::Field;
use ragu_core::{
    drivers::Coeff,
    maybe::{Maybe, MaybeKind},
};

/// Extension trait for `Maybe` that provides helper methods kept internal to
/// this crate.
pub(crate) trait InternalMaybe<T: Send>: Maybe<T> {
    /// Convert a `bool` into a `Field` element.
    fn fe<F: Field>(&self) -> <<Self as Maybe<bool>>::Kind as MaybeKind>::Rebind<F>
    where
        Self: Maybe<bool>,
    {
        Maybe::<bool>::view(self).map(|b| if *b { F::ONE } else { F::ZERO })
    }

    /// Convert a `bool` into a `Coeff`.
    fn coeff<F: Field>(&self) -> <<Self as Maybe<bool>>::Kind as MaybeKind>::Rebind<Coeff<F>>
    where
        Self: Maybe<bool>,
    {
        Maybe::<bool>::view(self).map(|b| if *b { Coeff::One } else { Coeff::Zero })
    }
}

impl<T: Send, M: Maybe<T>> InternalMaybe<T> for M {}
