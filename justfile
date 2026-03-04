run *ARGS:
  cargo run -- {{ARGS}}

build:
  cargo build

build_release:
  cargo build --release

test:
  cargo test

gen:
  python3 gen_rust.py
  python3 gen_data.py

bench_what *ARGS:
  uvx pywhat {{ARGS}}

bench_nth *ARGS:
  uvx --from name-that-hash nth {{ARGS}}
