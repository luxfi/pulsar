# Build stage
FROM golang:1.26-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN make build

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -g 1000 ringtail && \
    adduser -D -u 1000 -G ringtail ringtail

# Copy binary from builder
COPY --from=builder /app/bin/ringtail /usr/local/bin/ringtail

# Switch to non-root user
USER ringtail

# Set entrypoint
ENTRYPOINT ["ringtail"]

# Default command (local simulation)
CMD ["l", "0", "0"]