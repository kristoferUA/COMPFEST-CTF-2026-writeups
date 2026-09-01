#!/bin/sh
set -eu

IMAGE=compfest18-tes
CONTAINER=compfest18-tes
PORT=${PORT:-8080}

docker build -t "$IMAGE" .
docker rm -f "$CONTAINER" 2>/dev/null || true
exec docker run --rm -d --cap-add=SYS_PTRACE \
    --name "$CONTAINER" -p "$PORT:8080" "$IMAGE"
