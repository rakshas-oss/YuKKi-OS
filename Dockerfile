FROM rust:1.98.0-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY benches ./benches
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home yukki
COPY --from=build /src/target/release/yukki_core_node /usr/local/bin/yukki_core_node
USER 10001
ENTRYPOINT ["/usr/local/bin/yukki_core_node"]
