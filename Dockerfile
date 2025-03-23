FROM rust:alpine AS builder

ENV HOME=/home/root
WORKDIR $HOME/app

RUN apk add musl-dev

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/home/root/app/target \
    cargo build --release && cp /home/root/app/target/release/ssh-honeypot /home/root/app/ssh-honeypot

FROM scratch

USER 1000:1000

COPY --from=builder --chown=1000:1000 /home/root/app/ssh-honeypot /ssh-honeypot

EXPOSE 2222

ENTRYPOINT ["/ssh-honeypot"]
