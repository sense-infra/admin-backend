# Final stage
FROM alpine:3.21.3

# Install runtime dependencies
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 -S app && \
    adduser -u 1000 -S app -G app

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY app/servicebin /app/servicebin

# Change ownership
RUN chown -R app:app /app

# Switch to non-root user
USER app
