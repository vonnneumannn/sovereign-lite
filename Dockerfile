# Build stage
FROM rust:1.75-slim-bookworm as builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy source
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build release binary
RUN cargo build --release --bin sovereign-relay

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/sovereign-relay /app/sovereign-relay

# Expose port
EXPOSE 8765

# Run the relay server
CMD ["./sovereign-relay", "--host", "0.0.0.0", "--port", "8765"]
