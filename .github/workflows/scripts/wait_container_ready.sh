#!/bin/bash

container_name=$1
timeout=$2

start_time=$(date +%s)

while true; do
  echo "Waiting on $container_name container to finish setup..."
  # Check if the file exists inside the container
  if docker exec "$container_name" test -f "/root/.setup"; then
    echo "$container_name container is ready"
    break
  fi

  current_time=$(date +%s)
  elapsed=$(( current_time - start_time ))

  # Check if timeout exceeded
  if (( elapsed >= timeout )); then
    echo "Timeout reached after $timeout seconds waiting for $container_name container."
    exit 1
  fi
  sleep 5
done
