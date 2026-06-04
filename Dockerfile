FROM rust:alpine AS chef
RUN cargo install cargo-chef
RUN apk add musl-dev pkgconfig openssl-dev openssl-libs-static

FROM chef AS planner
WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
# Dependencies compiled here become a cached layer — only re-runs when Cargo.toml/Cargo.lock change
RUN cargo chef cook --release --bin ssh-honeypot --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin ssh-honeypot && \
    cp target/release/ssh-honeypot /ssh-honeypot

FROM scratch

USER 1000:1000

COPY --from=builder --chown=1000:1000 /ssh-honeypot /ssh-honeypot

EXPOSE 2222

ENTRYPOINT ["/ssh-honeypot"]
