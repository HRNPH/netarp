# Build from source (local dev / automated builds). For the tiny
# production image built by CI from a prebuilt static binary, see
# Dockerfile.prebuilt.
FROM rust:1.89-slim AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY migration ./migration
COPY src ./src

RUN cargo build --release

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/target/release/netarp /usr/local/bin/netarp

VOLUME ["/var/lib/netarp"]
ENTRYPOINT ["/usr/local/bin/netarp"]
