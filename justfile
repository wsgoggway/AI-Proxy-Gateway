# AI Proxy — standard dev commands

default: build

# ─── Build ────────────────────────────────────────────────
# Build everything: 4 CLI platforms + local apx + proxy binary
build:
    cd cli && bash build-all.sh
    cd cli && go build -o ~/.local/bin/apx .
    cd proxy && cargo build --release

mitm:
    cd proxy && cargo run --release

# ─── Test ─────────────────────────────────────────────────
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

# ─── Deploy ───────────────────────────────────────────────
# Build + push proxy binary to server
deploy: build
    scp -F /dev/null -o "StrictHostKeyChecking=no" proxy/target/release/ai-proxy root@ai-prx.warsong.me:/tmp/ai-proxy-new
    ssh -F /dev/null root@ai-prx.warsong.me 'systemctl stop ai-proxy && cp /tmp/ai-proxy-new /opt/ai-proxy/ai-proxy && systemctl start ai-proxy && sleep 1 && systemctl is-active ai-proxy'

# ─── Security ─────────────────────────────────────────────
audit:
    cd proxy && cargo audit
