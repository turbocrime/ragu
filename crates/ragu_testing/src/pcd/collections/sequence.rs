//! Test fixtures for sequence concatenation over coefficient polynomials: a
//! sequence is represented by the polynomial whose coefficients are its
//! members in order (`[s_0, .., s_{L-1}]` ↦ `Σ s_i·Xⁱ`), so concatenating
//! two sequences is a shifted addition:
//!
//! ```text
//! C = A + X^{|A|} · B
//! ```
//!
//! The runtime offset `X^{|A|}` is itself a **committed monomial**, opened
//! at the Fiat–Shamir challenge like any polynomial — so the step spends no
//! in-circuit loop and no const-generic length; `z^{|A|}` arrives as a
//! claimed evaluation, `O(1)` whatever the length. Length arithmetic rides
//! the same trick: the output's token satisfies `M_c = M_a · M_b`
//! (`X^{|A|}·X^{|B|} = X^{|A|+|B|}`), one more multiplication of opened
//! values.
//!
//! **A length token needs no monomial proof.** `commit(Xⁿ)` is the `n`-th
//! host generator, so a token's canonical name is publicly recomputable
//! from the cycle parameters, and under binding the name *is* the proof
//! that the committed polynomial is exactly `Xⁿ`.
//!
//! Two steps, registered into the shared
//! [`collections_app`](super::collections_app):
//!
//! * [`SeedSequence`] — a leaf establishing an **initial** sequence: it
//!   witnesses the sequence polynomial and its length token and outputs
//!   both names in the header.
//! * [`ConcatSequences`] — a **fuse**: the contributing sequences and their
//!   tokens arrive as the children's header-carried names, the parent
//!   re-witnesses all four and enforces its handles' names equal the header
//!   wires, then proves the concatenation and the token product. Downstream
//!   consumers see only the output pair `(C, M_c)`.
//!
//! Ceilings at `ProductionRank` (`2^13 = 8192` coefficients): a sequence
//! alone can hold **8,192 members** (degree `≤ 8191`), but its length token
//! `X^L` needs degree `L`, so a length-threaded sequence holds at most
//! **8,191** — the same number as a multiset, for a different reason.

use core::marker::PhantomData;

use ff::{Field, PrimeField};
use ragu_arithmetic::{CryptoRngCore, Cycle};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pcd::{
    Pcd, PolyCommitment,
    header::{Header, Suffix},
    step::{Encoded, Index, Step, StepCtx},
};
use ragu_primitives::{
    Element, GadgetExt,
    allocator::{Allocator, Standard},
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

use super::CollectionsApp;

/// The coefficient polynomial of a sequence: member `i` is the coefficient
/// of `Xⁱ`. A sequence of `L` members is a polynomial of degree `< L`.
///
/// The all-zero sequence commits to the identity, which the framework
/// rejects — real sequence encodings avoid it (e.g. tachyon's sentinel
/// coefficient); the fixtures simply use nonzero members.
pub fn sequence_polynomial<F: PrimeField, R: Rank>(members: &[F]) -> sparse::Polynomial<F, R> {
    sparse::Polynomial::from_coeffs(members.to_vec())
}

/// The length token `Xⁿ`: the monomial whose committed name any consumer
/// can recompute from the cycle parameters.
///
/// Panics (via `from_coeffs`) when `n + 1` exceeds the rank's coefficient
/// capacity — the reason a length-threaded sequence caps at
/// `num_coeffs − 1` members.
pub fn length_token<F: PrimeField, R: Rank>(n: usize) -> sparse::Polynomial<F, R> {
    let mut coeffs = vec![F::ZERO; n + 1];
    coeffs[n] = F::ONE;
    sparse::Polynomial::from_coeffs(coeffs)
}

/// Data carried by a [`SeqHeader`]: the sequence's name, its length token's
/// name, and the member list as unstructured PCD data.
pub struct SeqData<F: Field> {
    pub coords: [F; 2],
    pub token_coords: [F; 2],
    pub members: Vec<F>,
}

impl<F: Field> Clone for SeqData<F> {
    fn clone(&self) -> Self {
        Self {
            coords: self.coords,
            token_coords: self.token_coords,
            members: self.members.clone(),
        }
    }
}

impl<F: Field> SeqData<F> {
    /// The four header elements in layout order: sequence name, then token
    /// name.
    fn header_element(&self, i: usize) -> F {
        match i {
            0 | 1 => self.coords[i],
            _ => self.token_coords[i - 2],
        }
    }
}

/// Header carrying a sequence's **name pair** — the sequence's coordinates
/// and its length token's — as four raw elements, so a parent can
/// `enforce_equal` its handles against the child's header wires.
pub struct SeqHeader;

impl<F: Field> Header<F> for SeqHeader {
    const SUFFIX: Suffix = Suffix::new(2);
    type Data = SeqData<F>;
    type Output = Kind![F; FixedVec<Element<'_, _>, ConstLen<4>>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        ConstLen::<4>::range()
            .map(|i| Element::alloc(dr, allocator, witness.as_ref().map(|d| d.header_element(i))))
            .try_collect_fixed()
    }
}

/// Witness for [`SeedSequence`]: the initial sequence and its length token,
/// each as a committed polynomial.
pub struct SeedSequenceWitness<C: Cycle, R: Rank> {
    pub sequence: PolyCommitment<C, R>,
    pub token: PolyCommitment<C, R>,
    pub members: Vec<C::CircuitField>,
}

/// A leaf establishing an initial sequence: witnesses the sequence
/// polynomial and its length token, and outputs both names in the header.
pub struct SeedSequence<C, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C, R> SeedSequence<C, R> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C, R> Default for SeedSequence<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Cycle, R: Rank> Step<C> for SeedSequence<C, R> {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = SeedSequenceWitness<C, R>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = SeqHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, ()>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let members = witness.as_ref().map(|w| w.members.clone());
        let seq_com = witness.as_ref().map(|w| w.sequence.clone());
        let token_com = witness.map(|w| w.token.clone());
        let [seq, token] = ctx.witness_polynomial::<R, 2>([seq_com, token_com])?;

        let output_data = build_seq_data(&seq, &token, members);
        let header = name_pair_header(&seq, &token)?;

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(header),
            ),
            output_data,
            D::unit(),
        ))
    }
}

/// Witness for the [`ConcatSequences`] fuse: the contributing sequences and
/// tokens (which must match the children's header-carried names) and the
/// claimed output pair.
pub struct ConcatSequencesWitness<C: Cycle, R: Rank> {
    pub a: PolyCommitment<C, R>,
    pub b: PolyCommitment<C, R>,
    pub a_token: PolyCommitment<C, R>,
    pub b_token: PolyCommitment<C, R>,
    pub output: PolyCommitment<C, R>,
    pub output_token: PolyCommitment<C, R>,
}

/// The concatenation fuse: takes two [`SeqHeader`] children, binds its four
/// witnessed inputs to the children's names in-circuit, proves
/// `C = A + M_a·B` and `M_c = M_a·M_b`, and outputs the pair `(C, M_c)`
/// alone.
pub struct ConcatSequences<C, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C, R> ConcatSequences<C, R> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C, R> Default for ConcatSequences<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Cycle, R: Rank> Step<C> for ConcatSequences<C, R> {
    const INDEX: Index = Index::new(3);
    type Witness<'source> = ConcatSequencesWitness<C, R>;
    type Aux<'source> = ();
    type Left = SeqHeader;
    type Right = SeqHeader;
    type Output = SeqHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, SeqData<C::CircuitField>>,
        right: DriverValue<D, SeqData<C::CircuitField>>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();

        let members = D::try_just(|| {
            let mut members = left.as_ref().take().members.clone();
            members.extend(right.as_ref().take().members.iter().copied());
            Ok(members)
        })?;
        let left_encoded = Encoded::new(ctx.dr, allocator, left)?;
        let right_encoded = Encoded::new(ctx.dr, allocator, right)?;

        let a_com = witness.as_ref().map(|w| w.a.clone());
        let b_com = witness.as_ref().map(|w| w.b.clone());
        let ta_com = witness.as_ref().map(|w| w.a_token.clone());
        let tb_com = witness.as_ref().map(|w| w.b_token.clone());
        let c_com = witness.as_ref().map(|w| w.output.clone());
        let tc_com = witness.map(|w| w.output_token.clone());
        let [a, b, ta, tb, c, tc] =
            ctx.witness_polynomial::<R, 6>([a_com, b_com, ta_com, tb_com, c_com, tc_com])?;

        // The cross-proof identity checks: each witnessed input's name
        // equals the corresponding child header wire — sequence and token,
        // both children.
        for (handle, child, offset) in [
            (&a, &left_encoded, 0),
            (&ta, &left_encoded, 2),
            (&b, &right_encoded, 0),
            (&tb, &right_encoded, 2),
        ] {
            let name = handle.coords();
            let header: &FixedVec<Element<'dr, D>, ConstLen<4>> = child.as_gadget();
            name[0].enforce_equal(ctx.dr, &header[offset])?;
            name[1].enforce_equal(ctx.dr, &header[offset + 1])?;
        }

        // z binds all six names: both outputs' commitments are fixed before
        // the evaluation point is known.
        let mut inputs = Vec::with_capacity(12);
        for handle_coords in [
            a.coords(),
            b.coords(),
            ta.coords(),
            tb.coords(),
            c.coords(),
            tc.coords(),
        ] {
            inputs.extend(handle_coords);
        }
        let z = ctx.derive_challenge(&inputs)?;

        // Open the contributing sequences and both input tokens at z.
        let mut open = |ctx: &mut StepCtx<'_, 'dr, D, C>,
                        handle: &ragu_pcd::PolyHandle<'dr, D, C, R>|
         -> Result<Element<'dr, D>> {
            let y_value = z
                .value()
                .map(|z| *z)
                .and_then(|z| handle.polynomial().as_ref().map(|p| p.eval(z)));
            let y = Element::alloc(ctx.dr, allocator, y_value)?;
            ctx.enforce_poly_query(handle, z.clone(), y.clone())?;
            Ok(y)
        };
        let y_a = open(ctx, &a)?;
        let y_b = open(ctx, &b)?;
        let y_ta = open(ctx, &ta)?;
        let y_tb = open(ctx, &tb)?;

        // The outputs' claims: C evaluates to a(z) + m_a(z)·b(z), and the
        // output token to m_a(z)·m_b(z). A wrong output makes its claim
        // false by Schwartz–Zippel over z.
        let shifted_b = y_ta.mul(ctx.dr, &y_b)?;
        let y_c = y_a.add(ctx.dr, &shifted_b);
        ctx.enforce_poly_query(&c, z.clone(), y_c)?;
        let y_tc = y_ta.mul(ctx.dr, &y_tb)?;
        ctx.enforce_poly_query(&tc, z, y_tc)?;

        // The output header is the pair (C, M_c) — sequence identity and
        // length token — and nothing about the contributors.
        let output_data = build_seq_data(&c, &tc, members);
        let header = name_pair_header(&c, &tc)?;

        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(header)),
            output_data,
            D::unit(),
        ))
    }
}

/// Assembles a [`SeqData`] value from the two handles' names and the member
/// list.
fn build_seq_data<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, R: Rank>(
    seq: &ragu_pcd::PolyHandle<'dr, D, C, R>,
    token: &ragu_pcd::PolyHandle<'dr, D, C, R>,
    members: DriverValue<D, Vec<D::F>>,
) -> DriverValue<D, SeqData<D::F>> {
    let [s0, s1] = seq.coords();
    let [t0, t1] = token.coords();
    let s0 = s0.value().map(|v| *v);
    let s1 = s1.value().map(|v| *v);
    let t0 = t0.value().map(|v| *v);
    let t1 = t1.value().map(|v| *v);
    s0.and_then(|s0| {
        s1.and_then(|s1| {
            t0.and_then(|t0| {
                t1.and_then(|t1| {
                    members.map(|members| SeqData {
                        coords: [s0, s1],
                        token_coords: [t0, t1],
                        members,
                    })
                })
            })
        })
    })
}

/// The four header wires for a sequence's name pair — the handles' own
/// coordinate wires, reused rather than re-allocated.
fn name_pair_header<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, R: Rank>(
    seq: &ragu_pcd::PolyHandle<'dr, D, C, R>,
    token: &ragu_pcd::PolyHandle<'dr, D, C, R>,
) -> Result<FixedVec<Element<'dr, D>, ConstLen<4>>> {
    seq.coords()
        .into_iter()
        .chain(token.coords())
        .collect::<Vec<_>>()
        .try_into()
}

/// Seed an initial sequence from its member list.
pub fn seed_sequence<C: Cycle, R: Rank, RNG: CryptoRngCore>(
    app: &CollectionsApp<'_, C, R>,
    rng: &mut RNG,
    members: &[C::CircuitField],
) -> Result<Pcd<C, R, SeqHeader>> {
    let (leaf, ()) = app.seed(
        rng,
        SeedSequence::new(),
        SeedSequenceWitness {
            sequence: app.commit_polynomial(&sequence_polynomial(members))?,
            token: app.commit_polynomial(&length_token(members.len()))?,
            members: members.to_vec(),
        },
    )?;
    Ok(leaf)
}

/// Fuse two sequence children into their concatenation, computing the
/// output pair honestly from the members the children carry.
pub fn fuse_concat<C: Cycle, R: Rank, RNG: CryptoRngCore>(
    app: &CollectionsApp<'_, C, R>,
    rng: &mut RNG,
    left: Pcd<C, R, SeqHeader>,
    right: Pcd<C, R, SeqHeader>,
) -> Result<Pcd<C, R, SeqHeader>> {
    let concatenated: Vec<C::CircuitField> = left
        .data()
        .members
        .iter()
        .chain(right.data().members.iter())
        .copied()
        .collect();
    let witness = ConcatSequencesWitness {
        a: app.commit_polynomial(&sequence_polynomial(&left.data().members))?,
        b: app.commit_polynomial(&sequence_polynomial(&right.data().members))?,
        a_token: app.commit_polynomial(&length_token(left.data().members.len()))?,
        b_token: app.commit_polynomial(&length_token(right.data().members.len()))?,
        output: app.commit_polynomial(&sequence_polynomial(&concatenated))?,
        output_token: app.commit_polynomial(&length_token(concatenated.len()))?,
    };
    let (out, ()) = app.fuse(rng, ConcatSequences::new(), witness, left, right)?;
    Ok(out)
}
