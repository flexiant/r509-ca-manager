#!/bin/sh
set -e

if [ "$1" = 'crl-server' ]; then
	sleep 5
	/usr/local/concerto/crl-server
else
	exec "$@"
fi
