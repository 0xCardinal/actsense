###############################################
# Stage 1: Build frontend assets with Node.js #
###############################################
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

# Install dependencies before copying the rest to leverage caching
# patch-package is invoked by rollup during postinstall; install it globally so npm ci succeeds
RUN npm install -g patch-package

COPY frontend/package*.json ./
RUN npm ci

# Copy source and build
COPY frontend/ ./
RUN npm run build

########################################
# Stage 2: Backend + bundled frontend #
########################################
FROM python:3.11-slim AS backend

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONPATH=/app/backend

WORKDIR /app

# System dependencies required by git operations in the auditor
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Install backend dependencies
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend source
COPY backend /app/backend

# Copy built frontend assets into expected location
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

# Create writable directories for analysis data
RUN mkdir -p /app/data/analyses /app/data/clones

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]

