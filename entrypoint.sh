#!/bin/sh
echo "STARTING"
export SECRET_KEY="$(cat /run/secrets/outline_secret_key)"
export UTILS_SECRET="$(cat /run/secrets/outline_utils_secret)"
export DATABASE_URL="postgres://$(cat /run/secrets/outline_db_username):$(cat /run/secrets/outline_db_password)@postgres:5432/outline?sslmode=disable&connect_timeout=5"
export OIDC_CLIENT_SECRET="$(cat /run/secrets/outline_oidc_client_secret)"
yarn db:migrate
exec "$@"
