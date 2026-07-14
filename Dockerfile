FROM rust:alpine AS chef
RUN apk add musl-dev pkgconfig openssl-dev openssl-libs-static
RUN cargo install cargo-chef --locked

FROM chef AS planner
WORKDIR /app
# Only manifests — no source or migration files, so the recipe stays
# stable for any change that doesn't touch Cargo.toml / Cargo.lock
COPY Cargo.toml Cargo.lock ./
COPY desktop/Cargo.toml desktop/
COPY common/Cargo.toml common/
COPY shell/Cargo.toml shell/
# cargo chef prepare needs the bin/lib entry-points to exist
RUN mkdir -p src/bin desktop/src/bin common/src shell/src && \
    touch src/lib.rs src/main.rs \
          src/bin/report_generator.rs \
          desktop/src/bin/dashboard-gui.rs desktop/src/bin/report-gui.rs \
          common/src/lib.rs shell/src/lib.rs
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
# This layer is cached as long as recipe.json (i.e. Cargo.toml / Cargo.lock) is unchanged
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo chef cook --release --bin ssh-honeypot --recipe-path recipe.json
# Full source comes in here; only user code is recompiled from this point
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --bin ssh-honeypot && \
    cp target/release/ssh-honeypot /ssh-honeypot && \
    mkdir /keys

FROM scratch

USER 1000:1000

COPY --from=builder --chown=1000:1000 /ssh-honeypot /ssh-honeypot
# Empty dir copied so the named-volume mount inherits 1000:1000 on first creation.
# RUN is not available in scratch — directory must come from the builder stage.
COPY --from=builder --chown=1000:1000 /keys /keys

EXPOSE 22
EXPOSE 2222

ENTRYPOINT ["/ssh-honeypot"]
