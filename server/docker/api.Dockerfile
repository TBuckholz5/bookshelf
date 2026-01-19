FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code.
COPY . .

# Build the application.
RUN CGO_ENABLED=0 go build -o main ./cmd/api

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests.
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/main .

# Copy the .env.toml file
COPY .env* ./
COPY migrations/ ./migrations/

# Expose port 8081
EXPOSE 8081

# Run the binary
CMD ["./main"]

