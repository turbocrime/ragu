use super::{MaybeCast, MaybeKind};

impl<U: Send, V: Send, K: MaybeKind> MaybeCast<(U, V), K> for (U, V) {
    type Output = (K::Rebind<U>, K::Rebind<V>);

    fn empty() -> Self::Output {
        (K::empty(), K::empty())
    }
    fn cast(self) -> Self::Output {
        (K::maybe_just(|| self.0), K::maybe_just(|| self.1))
    }
}

impl<U: Send, V: Send, W: Send, K: MaybeKind> MaybeCast<(U, V, W), K> for (U, V, W) {
    type Output = (K::Rebind<U>, K::Rebind<V>, K::Rebind<W>);

    fn empty() -> Self::Output {
        (K::empty(), K::empty(), K::empty())
    }
    fn cast(self) -> Self::Output {
        (
            K::maybe_just(|| self.0),
            K::maybe_just(|| self.1),
            K::maybe_just(|| self.2),
        )
    }
}

impl<U: Send, V: Send, W: Send, X: Send, K: MaybeKind> MaybeCast<(U, V, W, X), K> for (U, V, W, X) {
    type Output = (K::Rebind<U>, K::Rebind<V>, K::Rebind<W>, K::Rebind<X>);

    fn empty() -> Self::Output {
        (K::empty(), K::empty(), K::empty(), K::empty())
    }
    fn cast(self) -> Self::Output {
        (
            K::maybe_just(|| self.0),
            K::maybe_just(|| self.1),
            K::maybe_just(|| self.2),
            K::maybe_just(|| self.3),
        )
    }
}

impl<U: Send, V: Send, W: Send, X: Send, K: MaybeKind> MaybeCast<((U, V), (W, X)), K>
    for (U, V, W, X)
{
    type Output = (K::Rebind<(U, V)>, K::Rebind<(W, X)>);

    fn empty() -> Self::Output {
        (K::empty(), K::empty())
    }
    fn cast(self) -> Self::Output {
        (
            K::maybe_just(|| (self.0, self.1)),
            K::maybe_just(|| (self.2, self.3)),
        )
    }
}

impl<const N: usize, U: Send, K: MaybeKind> MaybeCast<[U; N], K> for [U; N] {
    type Output = [K::Rebind<U>; N];

    fn empty() -> Self::Output {
        core::array::from_fn(|_| K::empty())
    }
    fn cast(self) -> Self::Output {
        // TODO(ebfull): This can be done more efficiently with unsafe{} code,
        // since the two structures have identical layouts.
        let mut iter = self.into_iter();
        core::array::from_fn(|_| K::maybe_just(|| iter.next().expect("array lengths are the same")))
    }
}

#[cfg(test)]
use super::{Always, Empty, Maybe};

#[test]
fn test_2tuple() {
    let (a, b) = Always::maybe_just(|| (1usize, 2usize)).cast();
    assert_eq!(a.take(), 1);
    assert_eq!(b.take(), 2);
    let (Empty, Empty) = <Empty as Maybe<(usize, usize)>>::cast(Empty);
}

#[test]
fn test_3tuple() {
    let (a, b, c) = Always::maybe_just(|| (1usize, 2usize, 3usize)).cast();
    assert_eq!(a.take(), 1);
    assert_eq!(b.take(), 2);
    assert_eq!(c.take(), 3);
    let (Empty, Empty, Empty) = <Empty as Maybe<(usize, usize, usize)>>::cast(Empty);
}

#[test]
fn test_4tuple_full() {
    let (a, b, c, d) =
        Always::maybe_just(|| (1usize, 2usize, 3usize, 4usize)).cast::<(_, _, _, _)>();
    assert_eq!(a.take(), 1);
    assert_eq!(b.take(), 2);
    assert_eq!(c.take(), 3);
    assert_eq!(d.take(), 4);
    let (Empty, Empty, Empty, Empty) =
        <Empty as Maybe<(usize, usize, usize, usize)>>::cast::<(_, _, _, _)>(Empty);
}

#[test]
fn test_4tuple_split() {
    let (a, b) = Always::maybe_just(|| (1usize, 2usize, 3usize, 4usize)).cast::<((_, _), (_, _))>();
    assert_eq!(a.take(), (1, 2));
    assert_eq!(b.take(), (3, 4));
    let (Empty, Empty) =
        <Empty as Maybe<(usize, usize, usize, usize)>>::cast::<((_, _), (_, _))>(Empty);
}

#[test]
fn test_arr() {
    let [a, b, c] = Always::maybe_just(|| [1usize, 2usize, 3usize]).cast();
    assert_eq!(a.take(), 1);
    assert_eq!(b.take(), 2);
    assert_eq!(c.take(), 3);
    let [Empty, Empty, Empty] = <Empty as Maybe<[usize; 3]>>::cast(Empty);
}
