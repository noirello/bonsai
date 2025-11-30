#!/bin/bash

timeout=$1

start_time=$(date +%s)

while true; do
  echo "Waiting on LDAP server to response..."
  # Check if the file exists inside the container
  if ldapsearch -x -H "ldap://bonsai.test" -b "" -s base 'objectclass=*' > /dev/null 2>&1; then
    echo "LDAP Server has responded"
    break
  fi

  current_time=$(date +%s)
  elapsed=$(( current_time - start_time ))

  # Check if timeout exceeded
  if (( elapsed >= timeout )); then
    echo "Timeout reached after $timeout seconds waiting on LDAP Server"
    echo "INFO"
    docker exec server ps aux
    echo "----------------"
    docker logs server
    exit 1
  fi
  sleep 5
done