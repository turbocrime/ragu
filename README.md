<p align="center">
  <img width="300" height="80" src="https://tachyon.z.cash/assets/ragu/v1_github600x160.png">
</p>

---

# `ragu` ![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)

**Ragu** is a Rust-language [proof-carrying data (PCD)](https://ic-people.epfl.ch/~achiesa/docs/CT10.pdf) framework that implements a modified version of the ECDLP-based recursive SNARK construction from [Halo [BGH19]](https://eprint.iacr.org/2019/1021). Ragu does not use a trusted setup. Developed for use with the [Pasta curves](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/) used in [Zcash](https://z.cash/), and designed specifically for use in [Project Tachyon](https://tachyon.z.cash/), Ragu targets performance and feature support that is competitive with other ECC-based [accumulation](https://eprint.iacr.org/2020/499)/[folding](https://eprint.iacr.org/2021/370) schemes without complicated circuit arithmetizations.

> **Ragu is under heavy development and has not undergone auditing.** Do not use this software in production.

## License

This library is distributed under the terms of both the MIT license and the Apache License (Version 2.0). See [LICENSE-APACHE](./LICENSE-APACHE), [LICENSE-MIT](./LICENSE-MIT) and [COPYRIGHT](./COPYRIGHT).

[![codecov](https://codecov.io/gh/tachyon-zcash/ragu/graph/badge.svg?token=HJARL1P2O4)](https://codecov.io/gh/tachyon-zcash/ragu)