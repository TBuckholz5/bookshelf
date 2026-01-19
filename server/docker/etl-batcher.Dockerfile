FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code.
COPY . .

# Build the application.
RUN CGO_ENABLED=0 go build -o main ./cmd/etl/batcher

# Final stage
FROM alpine:latest

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/main .

# Copy the .env.toml file
COPY .env* ./

# Run the binary
CMD ["./main"]


