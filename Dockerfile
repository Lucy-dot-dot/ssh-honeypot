FROM rust:alpine AS chef
RUN cargo install cargo-chef
RUN apk add musl-dev pkgconfig openssl-dev openssl-libs-static

FROM chef AS planner
WORKDIR /app
# Only manifests — no source or migration files, so the recipe stays
# stable for any change that doesn't touch Cargo.toml / Cargo.lock
COPY Cargo.toml Cargo.lock ./
# cargo chef prepare needs the bin/lib entry-points to exist
RUN mkdir -p src/bin && \
    touch src/lib.rs src/main.rs \
          src/bin/report_generator.rs src/bin/report_gui.rs
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
# This layer is cached as long as recipe.json (i.e. Cargo.toml / Cargo.lock) is unchanged
RUN cargo chef cook --release --bin ssh-honeypot --recipe-path recipe.json
# Full source comes in here; only user code is recompiled from this point
COPY . .
RUN cargo build --release --bin ssh-honeypot && \
    cp target/release/ssh-honeypot /ssh-honeypot

FROM scratch

USER 1000:1000

COPY --from=builder --chown=1000:1000 /ssh-honeypot /ssh-honeypot

EXPOSE 2222

ENTRYPOINT ["/ssh-honeypot"]
