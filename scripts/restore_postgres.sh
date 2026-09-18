#!/bin/sh
set -eu
: "${STAGING_DATABASE_URL:?Set a clean staging-only database URL}"
: "${ALLOW_STAGING_RESTORE:?Set ALLOW_STAGING_RESTORE=yes after checking the destination}"
[ "$ALLOW_STAGING_RESTORE" = "yes" ] || { echo "Restore confirmation missing" >&2; exit 2; }
[ "$#" -eq 1 ] || { echo "Usage: restore_postgres.sh backup.dump" >&2; exit 2; }
case "${STAGING_DATABASE_URL%%\?*}" in
  */*_restore) ;;
  *) echo "Destination database name must end in _restore" >&2; exit 2 ;;
esac
pg_restore --exit-on-error --no-owner --no-acl --clean --if-exists --dbname "$STAGING_DATABASE_URL" "$1"
psql "$STAGING_DATABASE_URL" -v ON_ERROR_STOP=1 -c "SELECT 1 FROM users LIMIT 1" >/dev/null
psql "$STAGING_DATABASE_URL" -v ON_ERROR_STOP=1 -c "SELECT 1 FROM audit_logs LIMIT 1" >/dev/null
echo "Staging restore and key-table verification completed."
