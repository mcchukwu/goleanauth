#!/usr/bin/env bash
# Ensures the integration-test Postgres is running and that a dedicated test
# database exists. Safe to run repeatedly.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is required for integration tests" >&2
  exit 1
fi

docker compose up -d postgres

DB_USER=$(grep -E '^DB_USER=' .env | cut -d= -f2-)
TEST_DB_NAME=${TEST_DB_NAME:-goleanauth_test}

echo "waiting for postgres to become ready..."
for _ in $(seq 1 30); do
  if docker compose exec -T postgres pg_isready -U "$DB_USER" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if docker compose exec -T postgres psql -U "$DB_USER" -d postgres -tAc \
    "SELECT 1 FROM pg_database WHERE datname = '$TEST_DB_NAME'" | grep -q 1; then
  echo "test database $TEST_DB_NAME already exists"
else
  docker compose exec -T postgres createdb -U "$DB_USER" "$TEST_DB_NAME"
  echo "created test database $TEST_DB_NAME"
fi