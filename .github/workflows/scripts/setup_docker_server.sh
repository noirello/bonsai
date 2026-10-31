#!/usr/bin/env bash
set -e

if [ "$(uname)" = "Darwin" ]; then
    docker run --cap-add=NET_ADMIN -p 389:389 -p 636:636 -p 88:88/udp -p 749:749 -p 8000:8000 -d -h bonsai.test --name server bonsai
    HOST_IP=127.0.0.1
    sudo scutil --set HostName bonsai.test
else
    mkdir -p /tmp/bonsai
    sudo chown 2001:2000 /tmp/bonsai
    docker run --cap-add=NET_ADMIN -v /tmp/bonsai/:/home/ldap/run/:z -d -h bonsai.test --name server bonsai
    HOST_IP=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' server)
fi

sudo bash -c "printf '\n$HOST_IP        bonsai.test\n' >> /etc/hosts"
cat /etc/hosts
ping -c 2 bonsai.test
