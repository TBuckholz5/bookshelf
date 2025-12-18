FROM rust:1.91 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release


FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/server .
COPY .en[v] ./
COPY migrations ./
EXPOSE 3000
CMD ["./server"]

