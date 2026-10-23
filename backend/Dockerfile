FROM rust:1-alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig
WORKDIR /usr/src/app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release --locked && rm -rf src
COPY src src
COPY migrations migrations
RUN touch src/main.rs && cargo build --release --locked

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl \
    && addgroup -S -g 10001 acvs \
    && adduser -S -u 10001 -G acvs -H -h /app -s /sbin/nologin acvs
WORKDIR /app
# Owned by root and not writable by the app user: the process can run the binary but never change it.
COPY --from=builder /usr/src/app/target/release/server /app/server
USER 10001:10001
EXPOSE 8000
CMD ["./server"]
