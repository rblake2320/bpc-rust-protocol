# syntax=docker/dockerfile:1
# Rust 1.85.0 bookworm manifest-list digest, resolved 2026-10-21.
FROM rust:1.85.0-bookworm@sha256:0ff31c9ffa641a62e48d543fb00b4960955ea375f40776f40f585b89e654cc5e AS build
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --features gateway --bin bpc-gateway

# Debian bookworm-slim manifest-list digest, resolved 2026-10-21.
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && groupadd --gid 10001 bpc \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin bpc \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /source/target/release/bpc-gateway /usr/local/bin/bpc-gateway
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/bpc-gateway"]
CMD ["serve"]
