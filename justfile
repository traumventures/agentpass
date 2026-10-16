# agentpass build recipes. Requires: rustup target add wasm32-unknown-unknown; cargo install trunk

export NO_COLOR := "false"

# Build the web UI and the release binary (web UI embedded).
build: web
    cargo build --release -p agentpass

# Build the Yew web UI into crates/web/dist.
web:
    cd crates/web && trunk build --release

# Install agentpass into ~/.cargo/bin.
install: web
    cargo install --path crates/agentpass --locked

# Run all tests (unit, integration and browser end-to-end).
test: web
    cargo test --workspace
    cargo build -p agentpass
    cd e2e && npm ci && npx playwright test

# Memory-protection tests; need root (sudo) to inspect the daemon's memory.
test-memory: web
    cargo test -p agentpass --test memory -- --ignored --nocapture

lint:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
