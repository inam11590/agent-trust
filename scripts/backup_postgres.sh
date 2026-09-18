#!/bin/sh
set -eu
: "${DATABASE_URL:?Set DATABASE_URL from the secret store}"
: "${BACKUP_OUTPUT:?Set BACKUP_OUTPUT to an encrypted/private destination path}"
umask 077
pg_dump --format=custom --no-owner --no-acl --dbname "$DATABASE_URL" --file "$BACKUP_OUTPUT"
pg_restore --list "$BACKUP_OUTPUT" >/dev/null
echo "Backup created and archive structure verified."
