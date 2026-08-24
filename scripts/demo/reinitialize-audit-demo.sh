#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

docker compose exec -T backend python manage.py migrate
docker compose exec -T backend python manage.py seed_androgoat_finding_demo --dev-fixture --reinitialize

printf 'AUDIT_DEMO_REINITIALIZED=PASS\n'
