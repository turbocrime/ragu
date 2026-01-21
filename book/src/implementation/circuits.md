# Circuits

## The Circuit Trait

The `Circuit` trait is Ragu's internal abstraction for arithmetic circuit synthesis.
Consumers won't directly implement `Circuit`, and should implement `Step` and `Header` instead—the PCD framework wraps these into circuits automatically.

| Associated Type | Purpose |
|-----------------|---------|
| `Instance` | Public inputs (prover and verifier) |
| `Witness` | Private inputs (prover only) |
| `Output` | Gadget representing circuit output |
| `Aux` | Values carried into the resulting `Pcd` |

### Instance vs Witness

Both `instance()` and `witness()` must produce identical `Output` values for valid proofs:

- **instance()**: Computes expected output from public inputs (verifier's view)
- **witness()**: Computes output from private inputs (prover's view)

This enables security (verifier never sees witness) and efficiency (drivers can skip witness computation via `MaybeKind`).

## Constraint Model

Circuits use an R1CS-like constraint system:

- **Multiplication** (`dr.mul()`): Adds constraint $A \cdot B = C$
- **Addition** (`dr.add()`): Free—creates virtual wire as linear combination
- **Linear constraints** (`dr.enforce_zero()`): Requires linear combination equals zero

## Witness Structure

The witness $\v{r}$ is defined by $\v{a}, \v{b}, \v{c} \in \F^n$ where $n = 2^k$. Individual elements are _wires_—specifically _allocated wires_, because the prover commits to them.

Ragu defines $\v{r}$ as the concatenation $\v{c} || \v{\hat{b}} || \v{a} || \v{0^n}$, a [structured vector](../protocol/prelim/structured_vectors.md).

### Virtual Wires

Linear constraints are linear combinations of elements within $\v{a}, \v{b}, \v{c}$. Any linear combination can be considered a _virtual wire_ which imposes no cost.

### The `ONE` Wire

Circuits always have the specially-labelled `ONE` wire $\v{c}_0 = 1$, enforced with the [linear constraint](../protocol/prelim/cs.md#linear-constraints) $\v{c}_0 = \v{k}_0 = 1$.

## See Also

- [PCD Proofs](proofs.md) - The `Step` and `Header` traits users implement
- [Drivers](drivers/index.md) - How circuit code is interpreted
