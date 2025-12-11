#!/bin/sh
set -e

# Fix permissions on Railway volume
if [ -d /data ]; then
  echo "Adjusting permissions for /data..."
  chown -R www-data:www-data /data || true
  chmod 0775 /data || true
fi

# Pass control to the main container command
exec "$@"
