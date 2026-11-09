#!/usr/bin/env bash
# Build and publish the image to Docker Hub.
# Usage: ./publish.sh <dockerhub-user> <version> [--multiarch] [--no-latest] [--skip-tests]
# Auth: run `docker login -u <user>` first (use an access token), or export DOCKERHUB_TOKEN to login here.
set -euo pipefail
cd "$(dirname "$0")"

USER_NAME="${1:-}"; VERSION="${2:-}"; shift 2 || true
[[ -n "$USER_NAME" && -n "$VERSION" ]] || { echo "usage: $0 <dockerhub-user> <version> [--multiarch] [--no-latest] [--skip-tests]"; exit 1; }
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)?$ ]] || { echo "version must look like 1.2.3"; exit 1; }

MULTI=0; LATEST=1; TESTS=1
for a in "$@"; do case "$a" in
  --multiarch) MULTI=1;; --no-latest) LATEST=0;; --skip-tests) TESTS=0;;
  *) echo "unknown option: $a"; exit 1;; esac; done

IMAGE="$USER_NAME/ip-scanner"
TAGS=(-t "$IMAGE:$VERSION"); [[ $LATEST == 1 ]] && TAGS+=(-t "$IMAGE:latest")

# never ship secrets or local data
for f in .env data; do
  grep -qx "$f/\?" .dockerignore || { echo "ERROR: $f is not in .dockerignore"; exit 1; }
done

if [[ $TESTS == 1 ]]; then
  PY="${PYTHON:-python3}"   # set PYTHON=/path/to/venv/bin/python if deps live in a venv
  echo "==> running tests"; "$PY" -m pytest -q
fi

if [[ -n "${DOCKERHUB_TOKEN:-}" ]]; then
  echo "==> docker login"; printf '%s' "$DOCKERHUB_TOKEN" | docker login -u "$USER_NAME" --password-stdin
fi
docker info >/dev/null 2>&1 || { echo "ERROR: cannot talk to Docker daemon (permissions?)"; exit 1; }

LABELS=(--label "org.opencontainers.image.version=$VERSION" --label "org.opencontainers.image.created=$(date -u +%FT%TZ)")

if [[ $MULTI == 1 ]]; then
  echo "==> multi-arch build + push (amd64, arm64)"
  docker buildx inspect ipscanner-builder >/dev/null 2>&1 || docker buildx create --name ipscanner-builder >/dev/null
  docker buildx build --builder ipscanner-builder --platform linux/amd64,linux/arm64 "${LABELS[@]}" "${TAGS[@]}" --push .
else
  echo "==> build"; docker build "${LABELS[@]}" "${TAGS[@]}" .
  echo "==> smoke test (container must become healthy)"
  CID=$(docker run -d --rm -p 127.0.0.1:18080:8080 -e PORT=8080 -v "$(mktemp -d)":/data "$IMAGE:$VERSION")
  trap 'docker rm -f "$CID" >/dev/null 2>&1 || true' EXIT
  ok=0; for _ in $(seq 1 30); do
    curl -fsS http://127.0.0.1:18080/api/health >/dev/null 2>&1 && { ok=1; break; }; sleep 1; done
  [[ $ok == 1 ]] || { echo "ERROR: smoke test failed"; docker logs "$CID" | tail -20; exit 1; }
  docker rm -f "$CID" >/dev/null; trap - EXIT
  echo "==> push"
  docker push "$IMAGE:$VERSION"; [[ $LATEST == 1 ]] && docker push "$IMAGE:latest"
fi
echo "Done: $IMAGE:$VERSION"
