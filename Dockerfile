FROM rust:1.87-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add clippy

WORKDIR /app
COPY . .

RUN cargo build --release 2>&1
RUN cargo test --release 2>&1
RUN cargo clippy -- -W clippy::all 2>&1
