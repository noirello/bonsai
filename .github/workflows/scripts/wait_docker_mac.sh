#!/usr/bin/env bash

# refs:
# https://stackoverflow.com/a/35979292/425458

[[ $(uname) == 'Darwin' ]] || { echo "This function only runs on macOS." >&2; exit 2; }

echo "-- Starting Docker.app, if necessary..."

open -g -a /Applications/Docker.app || exit

# Wait for the server to start up, if applicable.
i=0
while ! docker system info &>/dev/null; do
  (( i++ == 0 )) && printf %s '-- Waiting for Docker to finish starting up...' || printf '.'
  sleep 1
done
(( i )) && printf '\n'

echo "-- Docker is ready."