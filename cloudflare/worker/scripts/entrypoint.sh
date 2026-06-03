#!/bin/sh
set -e

cd /app

PUID=${PUID:-1000}
PGID=${PGID:-1000}

mkdir -p /app/data

exec "$@"
