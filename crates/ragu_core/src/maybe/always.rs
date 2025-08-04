use super::{Maybe, MaybeCast, MaybeKind};

/// The kind of `Maybe<T>` that represents a value that exists. This is
/// guaranteed by the compiler to have the same size and memory layout as `T`
/// itself.
#[repr(transparent)]
pub struct Always<T: Send>(T);

impl MaybeKind for Always<()> {
    type Rebind<T: Send> = Always<T>;

    fn empty<T: Send>() -> Self::Rebind<T> {
        // See the comment in `Empty::take`.
        const { panic!("MaybeKind::empty called on AlwaysKind") }
    }
}

impl<T: Send> Maybe<T> for Always<T> {
    type Kind = Always<()>;

    fn just<R: Send>(f: impl FnOnce() -> R) -> <Self::Kind as MaybeKind>::Rebind<R> {
        Always(f())
    }
    fn with<R: Send, E>(
        f: impl FnOnce() -> Result<R, E>,
    ) -> Result<<Self::Kind as MaybeKind>::Rebind<R>, E> {
        Ok(Always(f()?))
    }
    fn take(self) -> T {
        self.0
    }
    fn map<U: Send, F>(self, f: F) -> <Self::Kind as MaybeKind>::Rebind<U>
    where
        F: FnOnce(T) -> U,
    {
        Always(f(self.0))
    }
    fn into<U: Send>(self) -> <Self::Kind as MaybeKind>::Rebind<U>
    where
        T: Into<U>,
    {
        Always(self.0.into())
    }
    fn clone(&self) -> Self
    where
        T: Clone,
    {
        Always(self.0.clone())
    }
    fn and_then<U: Send, F>(self, f: F) -> <Self::Kind as MaybeKind>::Rebind<U>
    where
        F: FnOnce(T) -> <Self::Kind as MaybeKind>::Rebind<U>,
    {
        f(self.0)
    }
    fn view(&self) -> <Self::Kind as MaybeKind>::Rebind<&T>
    where
        T: Sync,
    {
        Always(&self.0)
    }
    fn view_mut(&mut self) -> <Self::Kind as MaybeKind>::Rebind<&mut T> {
        Always(&mut self.0)
    }

    fn cast<R>(self) -> T::Output
    where
        T: MaybeCast<R, Self::Kind>,
    {
        T::cast(self.0)
    }
}
