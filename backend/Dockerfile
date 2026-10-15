FROM rust:1-alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig
WORKDIR /usr/src/app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release --locked && rm -rf src
COPY src src
COPY migrations migrations
RUN touch src/main.rs && cargo build --release --locked

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl
WORKDIR /app
COPY --from=builder /usr/src/app/target/release/server /app/server
EXPOSE 8000
CMD ["./server"]
