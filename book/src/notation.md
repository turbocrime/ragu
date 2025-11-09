# Notation

## Vectors

We write a vector $\v{a} \in \F^n$ in bold type, and generally use capital
letters like $\v{G} \in \mathbb{G}^n$ to represent vectors of group elements.
Similarly, individual field and group elements are written in a normal typeface
like $a \in \F$ or $H \in \mathbb{G}$. All vectors are zero-indexed.

### Reversed Vector Notation

Given a vector $\v{a} \in \F^n$ we denote its reverse (mirror) as $\v{\hat{a}}$
such that $\v{\hat{a}}_i = \v{a}_{n - 1 - i} \forall i$.

### Mirrored Dot Product

We use a special notation $\revdot{\v{a}}{\v{b}}$ to denote
$\dot{\v{a}}{\v{\hat{b}}} = \dot{\v{\hat{a}}}{\v{b}}$.

## Polynomials

Given a univariate polynomial $p \in \F[X]$ of maximal degree $n - 1$ there
exists a (canonical) coefficient vector $\v{p} \in \F^n$ ordered such that
$\v{p}_{n - 1}$ is the leading coefficient. Given $z \in \F$ the evaluation
$p(z)$ is thus given by the inner (dot) product $\langle \v{p}, \v{z^n} \rangle$
where $\v{z^n}$ denotes the power vector $(z^0, z^1, \cdots, z^{n - 1})$. We
write the _dilation_ $p(zX)$ using the Hadamard (pairwise) product $\v{z^n}
\circ \v{p}$.