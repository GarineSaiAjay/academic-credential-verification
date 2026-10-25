FROM rust:1-alpine@sha256:b1d5dd5a22a09404d3e798c0cf051b689077360374eb505fa5bb93c479693d87 AS builder
RUN apk add --no-cache musl-dev pkgconfig
WORKDIR /usr/src/app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release --locked && rm -rf src
COPY src src
COPY migrations migrations
RUN touch src/main.rs && cargo build --release --locked

FROM alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates curl openssl \
    && addgroup -S -g 10001 acvs \
    && adduser -S -u 10001 -G acvs -H -h /app -s /sbin/nologin acvs
WORKDIR /app
# Owned by root and not writable by the app user: the process can run the binary but never change it.
COPY --from=builder /usr/src/app/target/release/server /app/server
USER 10001:10001
EXPOSE 8000
CMD ["./server"]
