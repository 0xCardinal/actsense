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
# Stage 2: Backend + bundled frontend  #
########################################
FROM python:3.12-slim AS backend

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONPATH=/app/backend

WORKDIR /app

# System dependencies required by git operations in the auditor
RUN apt-get update && \
    apt-get install -y --no-install-recommends git curl && \
    rm -rf /var/lib/apt/lists/*

# Install uv and copy to /usr/local/bin for easy access
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    if [ -f /root/.cargo/bin/uv ]; then \
        cp /root/.cargo/bin/uv /usr/local/bin/uv && \
        chmod +x /usr/local/bin/uv; \
    elif [ -f /root/.local/bin/uv ]; then \
        cp /root/.local/bin/uv /usr/local/bin/uv && \
        chmod +x /usr/local/bin/uv; \
    else \
        find /root -name uv -type f -executable 2>/dev/null | head -1 | xargs -I {} cp {} /usr/local/bin/uv && \
        chmod +x /usr/local/bin/uv; \
    fi && \
    uv --version

# Set PATH to include uv
ENV PATH="/usr/local/bin:/root/.cargo/bin:$PATH"

# Copy backend project files (pyproject.toml and uv.lock for dependency installation)
COPY backend/pyproject.toml backend/uv.lock /app/backend/

# Install backend dependencies using uv (before copying source for better caching)
WORKDIR /app/backend
RUN uv sync --no-dev

# Copy backend source (pyproject.toml and uv.lock already exist, so this is safe)
COPY backend/ /app/backend/

# Copy built frontend assets into expected location
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

# Create writable directories for analysis data
RUN mkdir -p /app/data/analyses /app/data/clones

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

