# agentpass build recipes. Requires: rustup target add wasm32-unknown-unknown; cargo install trunk

export NO_COLOR := "false"

# Build the release binary (embeds the committed web UI from crates/agentpass/ui).
build:
    cargo build --release -p agentpass

# Build the Yew web UI into crates/agentpass/ui (committed) and record its source hash.
web:
    rm -rf crates/agentpass/ui target/wasm-bindgen
    cd crates/web && trunk build --release
    AGENTPASS_WRITE_UI_HASH=1 cargo check -q -p agentpass

# Install agentpass into ~/.cargo/bin.
install:
    cargo install --path crates/agentpass --locked

# Run all tests (unit, integration and browser end-to-end).
test:
    cargo test --workspace
    cargo build -p agentpass
    cd e2e && npm ci && npx playwright test

# Memory-protection tests; need root (sudo) to inspect the daemon's memory.
test-memory:
    cargo test -p agentpass --test memory -- --ignored --nocapture

lint:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
