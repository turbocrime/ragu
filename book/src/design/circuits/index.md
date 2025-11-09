# Arithmetic Circuits

Ragu reduces arithmetic circuits to a set of constraints over a witness assignment $\v{r} \in \F^{4n}$ where the domain size $n = 2^k$ is parameterized by a positive integer $k$. For simplicity, we assume all circuits use the same $n$ (even though individual circuits may only require a smaller minimum $n$ for their reduction). 

The prover demonstrates knowledge of a witness for a given public input vector $\v{k}$ that encodes the instance of the satisfiability problem.
