set shell := ["bash", "-c"]

# Show available commands
default:
    @just --list

# Manage docs server (up, down, status)
docs action:
    @if [ "{{action}}" = "up" ]; then \
        echo "Starting docs server..."; \
        (cd docs && nohup hugo server --config hugo.yaml > hugo.log 2>&1 & echo $! > .hugo.pid); \
        echo "Docs server started at http://localhost:1313 (logs in docs/hugo.log)"; \
    elif [ "{{action}}" = "down" ]; then \
        echo "Stopping docs server..."; \
        if [ -f docs/.hugo.pid ]; then kill $(cat docs/.hugo.pid) 2>/dev/null || true; rm docs/.hugo.pid; else pkill -f "hugo server" || true; fi; \
        echo "Docs server stopped."; \
    elif [ "{{action}}" = "status" ]; then \
        if pgrep -f "hugo server" > /dev/null; then \
            echo "Docs server is RUNNING."; \
        else \
            echo "Docs server is STOPPED."; \
        fi; \
    else \
        echo "Unknown action: {{action}}. Use 'up', 'down', or 'status'."; \
        exit 1; \
    fi

# Manage actsense docker containers (up, down, status)
actsense action:
    @if [ "{{action}}" = "up" ]; then \
        echo "Starting actsense docker containers..."; \
        docker compose up -d; \
    elif [ "{{action}}" = "down" ]; then \
        echo "Stopping actsense docker containers..."; \
        docker compose down; \
    elif [ "{{action}}" = "status" ]; then \
        echo "Actsense docker containers status:"; \
        docker compose ps; \
    else \
        echo "Unknown action: {{action}}. Use 'up', 'down', or 'status'."; \
        exit 1; \
    fi

# Spin up docs and actsense
up:
    @just actsense up
    @just docs up

# Spin down docs and actsense
down:
    @just actsense down
    @just docs down

# Check status of docs and actsense
status:
    @just actsense status
    @just docs status
