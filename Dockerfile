# SupplyGuard Docker image
# Rust stable ≥ 1.85, build + test runner
FROM rust:1.85-bookworm

# Install minimal OS deps (SQLite bundled via rusqlite "bundled" feature, but we
# need build tools for the C compiler sqlite3-sys invokes during `cargo build`).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Pre-fetch deps (cached across rebuilds when Cargo.toml / Cargo.lock don't change)
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
COPY fixtures ./fixtures
COPY docs ./docs
COPY ui ./ui

# Run `cargo fetch` so the deps layer is cached.  The dummy main.rs trick avoids
# re-downloading crates every time a source file changes.
RUN mkdir -p src/bin \
    && echo "fn main() {}" > src/bin/sg-dummy.rs \
    && cargo fetch --locked \
    && rm src/bin/sg-dummy.rs

# Default: run the full test suite
CMD ["cargo", "test", "--locked", "--verbose"]
