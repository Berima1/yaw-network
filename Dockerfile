BLOCKCHAIN DOCKERFILE
# Ubuntu-based container optimized for African networks

FROM node:18-alpine AS base

# Install security updates and essential packages
RUN apk update && apk upgrade && \
    apk add --no-cache \
    curl \
    git \
    python3 \
    make \
    g++ \
    && rm -rf /var/cache/apk/*

# Create Ubuntu user for security
RUN addgroup -g 1001 -S ubuntu && \
    adduser -S ubuntu -u 1001 -G ubuntu

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Copy application code
COPY --chown=ubuntu:ubuntu . .

# Security hardening
RUN chown -R ubuntu:ubuntu /app
USER ubuntu

# Health check for African resilience
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Expose port
EXPOSE 3000

# Environment labels
LABEL org.opencontainers.image.title="Yaw Network - African Blockchain"
LABEL org.opencontainers.image.description="Ubuntu Consensus Blockchain built in Africa"
LABEL org.opencontainers.image.version="1.0.0-african-genesis"
LABEL org.opencontainers.image.authors="team@yawnetwork.org"
LABEL org.opencontainers.image.url="https://yawnetwork.org"
LABEL org.opencontainers.image.source="https://github.com/yaw-network/yaw-blockchain"
LABEL maintainer="Yaw Network Team <team@yawnetwork.org>"

# Start the African blockchain revolution!
CMD ["node", "server.js"]