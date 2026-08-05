# AI Proxy — standard dev commands

default: build

# ─── Rust: proxy + DPI core ───────────────────────────────
build:
    cd cli && bash build-all.sh
    cd proxy && cargo build --release

mitm:
    cd proxy && cargo run --release

test:
    cd proxy && cargo test

test-integration:
    cd proxy && cargo test --test '*' -- --test-threads=1

lint:
    cd proxy && cargo clippy -- -D warnings

fmt:
    cd proxy && cargo fmt --all -- --check

clean:
    cd proxy && cargo clean

# ─── CA without root (per-process isolation) ──────────────
# Install apx + CA to ~/.local/bin without root:
install-user host="localhost:8443":
    curl -sS http://{{host}}/install.sh | bash

# ─── Security ─────────────────────────────────────────────
audit:
    cd proxy && cargo audit
