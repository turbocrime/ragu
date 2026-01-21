# Rank-1 Constraint Systems

A **Rank-1 Constraint System** or R1CS is a circuit representation used in zero-knowledge proof systems.

Constraints are defined by *one* product, hence the name. A constraint is satisfied that witness vector $W$ is valid when:

$$
\langle A, W \rangle \cdot \langle B, W \rangle = \langle C, W \rangle
$$

Where $A$, $B$, and $C$ are vectors encoding the constraint as a relationship between elements of the witness vector.

Verbosely, the components may be expanded as:

$$
(a_0 w_0 + a_1 w_1 + \ldots + a_n w_n)
\times
(b_0 w_0 + b_1 w_1 + \ldots + b_n w_n)
=
(c_0 w_0 + c_1 w_1 + \ldots + c_n w_n)
$$

Where $a_i$, $b_i$, and $c_i$ are elements fixed at circuit synthesis and $w_i$ are elements of a witness.

A complete R1CS circuit is a collection of multiple $A$, $B$, and $C$ constraint vectors encoded as matrices $ \mathbf{A} $, $ \mathbf{B} $, and $ \mathbf{C} $.
The entire circuit is satisfied that $W$ is proven when:

$$
\mathbf{A}W \circ \mathbf{B}W = \mathbf{C}W
$$

## Wires

A **wire** refers to the correlating elements at index $i$ of these constraint vectors, and a wire's input value is the corresponding $i$ witness element.

The constraint coefficients $a_i$, $b_i$, $c_i$ specify how wire $i$ participates in a constraint, while a witness coefficient $w_i$ provides input for wire $i$ to constrain.

In order to allow reasoning about constant terms, $w_0 = 1$ is established.

## Example

Suppose we want to be able to prove knowledge of some $x$ such that $x^3 = y$.

### Decompose

Since $x \times x \times x = y$ requires two multiplications, we need to break it down.

Introduce an intermediate $t$ and we'll have two operations:

$$ x \times x = t $$
$$ t \times x = y $$

### Synthesis

Now considering $t$ and given $w_0 = 1$ we can say a four-element witness $W = [w_0, x, t, y]$ will provide the necessary inputs.
So constraint vectors $A$, $B$, and $C$ must correspondingly have four elements defining four wires.

A constraint $\langle A, W \rangle \cdot \langle B, W \rangle = \langle C, W \rangle$ expands to

$$

(a_0 w_0 + a_1 w_1 + a_2 w_2 + a_3 w_3)
\times
(b_0 w_0 + b_1 w_1 + b_2 w_2 + b_3 w_3)
=
(c_0 w_0 + c_1 w_1 + c_2 w_2 + c_3 w_3)
$$

Now synthesizing each constraint in this circuit, a coefficient of 1 selects that wire and 0 ignores it.
The decomposed operations are written as constraints:

$$
(0 w_0 + 1 x + 0 t + 0 y)
\times
(0 w_0 + 1 x + 0 t + 0 y)
=
(0 w_0 + 0 x + 1 t + 0 y)
$$

$$
(0 w_0 + 0 x + 1 t + 0 y)
\times
(0 w_0 + 1 x + 0 t + 0 y)
=
(0 w_0 + 0 x + 0 t + 1 y)
$$

### Encoding

Represent each constraint as three vectors of coefficients and compose those vectors into matrices:

$$
\mathbf{A} = \begin{bmatrix} 0 & 1 & 0 & 0 \\ 0 & 0 & 1 & 0 \end{bmatrix}
\quad
\mathbf{B} = \begin{bmatrix} 0 & 1 & 0 & 0 \\ 0 & 1 & 0 & 0 \end{bmatrix}
\quad
\mathbf{C} = \begin{bmatrix} 0 & 0 & 1 & 0 \\ 0 & 0 & 0 & 1 \end{bmatrix}
$$

This is the encoded R1CS circuit.

### Satisfying

I challenge you with public $y = 27$.
I demand a witness proving you know some $x$ such that $x^3 = y$.

Knowing secret $x = 3$, you send me

$$
W = [1, 3, 9, 27]
$$

I fill out the constraint template with values from the encoded circuit and your witness.

$$
(1 \times 3)
\times
(1 \times 3)
=
(1 \times 9)
$$

$$
(1 \times 9)
\times
(1 \times 3)
=
(1 \times 27)
$$

The constraints hold and I'm satisfied you know some appropriate $x$.

## Prime Fields

You didn't keep any secrets because $x$ is obviously visible as the second element in the witness.

In practice, R1CS operates over prime field $\mathbb{F}_p$ where $\mathbb{F}$ is a finite field of integers modulo prime $p$.
All coefficients ($a_i$, $b_i$, $c_i$, $w_i$) are elements of $\mathbb{F}_p$ and all arithmetic operations are performed modulo $p$.
This has several consequences not covered in this document.

Importantly, a valid witness cannot be guessed or brute-forced, but elements of a valid witness may be obfuscated by affine transformation into equivalent but meaningless elements.
This enables the prover to publish a witness that reveals nothing about private inputs.
