# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git build-base libpcap-dev

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binaries
RUN CGO_ENABLED=1 GOOS=linux go build -o /snortx ./cmd/cli
RUN CGO_ENABLED=1 GOOS=linux go build -o /snortx-api ./cmd/api

# Final stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates libpcap

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /snortx /usr/local/bin/
COPY --from=builder /snortx-api /usr/local/bin/

# Copy example config
COPY examples/snortx.yaml /app/

# Create output directory
RUN mkdir -p /app/output

# Expose API port
EXPOSE 8080

# Default to CLI help
ENTRYPOINT ["snortx"]
CMD ["--help"]
