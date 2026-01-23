# list all available just commands
default:
    @just --list

build *ARGS:
  cargo build {{ARGS}}

build_release *ARGS:
  cargo build --release --workspace --all-targets {{ARGS}}

lint:
  cargo clippy --workspace --lib --tests --benches --features test-fixtures -- -D warnings
  cargo fmt --all -- --check
  typos
  mdbook build ./book

fix:
  cargo fmt --all
  cargo fix --allow-dirty --allow-staged
  cargo clippy --fix --allow-dirty --allow-staged
  typos -w

_install_binstall:
  @cargo install cargo-binstall

_book_setup: _install_binstall
  @cargo binstall -y mdbook@0.4.52 mdbook-katex@0.9.4 mdbook-mermaid@0.16.2 mdbook-linkcheck@0.7.7 mdbook-admonish@1.20.0
  @cargo binstall -y typos-cli

_iai_setup: _install_binstall
  [ $(uname -s) == 'Darwin' ] || cargo binstall -y iai-callgrind-runner@0.16.1

# locally [build | serve | watch] Ragu book
book COMMAND: _book_setup
  mdbook {{COMMAND}} ./book --open

# run all tests
test *ARGS:
  cargo test --workspace --features test-fixtures {{ARGS}}

# run criterion benchmarks
bench-criterion *ARGS:
  cargo bench --workspace --features bench-criterion {{ARGS}}

_nixery_meta := if arch() == 'x86_64' { "shell" } else { "arm64/shell" }

# run iai benchmarks (auto-detects platform)
bench-iai *ARGS: _iai_setup
  [ $(uname -s) == 'Darwin' ] || cargo bench --workspace --features bench-iai {{ARGS}} 
  [ $(uname -s) != 'Darwin' ] || docker run --rm \
      -v "$PWD:/workspace:ro" \
      -v ragu-cargo:/.cargo \
      -v ragu-rustup:/.rustup \
      -v ragu-target:/workspace/target \
      -w /workspace \
      --security-opt seccomp=unconfined \
      nixery.dev/{{_nixery_meta}}/gcc/just/rustup/valgrind \
      sh -c 'just bench-iai {{ARGS}}'

# run CI checks locally (formatting, clippy, tests)
ci_local: _book_setup
  @echo "Running formatting check..."
  cargo fmt --all -- --check
  @echo "Running clippy..."
  cargo clippy --workspace --lib --tests --benches --locked --features test-fixtures -- -D warnings
  @echo "Running tests..."
  cargo test --release --all --locked --features test-fixtures
  @echo "Building benchmarks and examples..."
  cargo build --benches --examples --all-features
  @echo "Checking documentation..."
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all --locked --document-private-items
  @echo "Building book..."
  mdbook build ./book
  @echo "All CI checks passed!"
