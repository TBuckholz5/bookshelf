FROM lukemathwalker/cargo-chef:latest-rust-1.93-alpine AS chef
WORKDIR /app
RUN apk add --no-cache musl-dev

FROM chef AS planner
COPY etl/ .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY etl/ .
RUN cargo build --release --bin worker

FROM alpine:latest AS runtime
RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/target/release/worker ./worker

COPY .env* ./

CMD ["./worker"]

