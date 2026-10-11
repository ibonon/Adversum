# =============================================================================
# Adversum Frontend — Multi-stage Build (Vite + React 18 + Nginx)
# =============================================================================

# --- Stage 1: Build static assets ---
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies first for Docker cache optimization
COPY frontend/package*.json ./
RUN npm ci

# Copy frontend source files
COPY frontend/ ./

# Build production bundle
RUN npm run build

# --- Stage 2: Production Nginx Server ---
FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -q --spider http://localhost/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
