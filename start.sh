#!/usr/bin/env sh
cd "$(dirname "$0")" || exit 1
command -v node >/dev/null || { echo "Node.js 22.13+ is required (https://nodejs.org)"; exit 1; }
[ -f .env ] || cp .env.example .env
mkdir -p data
exec node --disable-warning=ExperimentalWarning server/index.js
