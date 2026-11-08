#!/usr/bin/env bash
# End-to-end demo on the local swarm. Usage: scripts/demo.sh [up|demo|down]
set -euo pipefail
cd "$(dirname "$0")/.."
STACK=da
client() { docker exec -i "$(docker ps -qf name=${STACK}_bridge | head -1)" da "$@"; }
count() { docker service ls --filter name=${STACK}_ --format '{{.Name}} {{.Replicas}}'; }

case "${1:-demo}" in
up)
  docker build -t da:dev .
  docker stack deploy --resolve-image never -c stack.yml $STACK
  echo "waiting for gossip..."; sleep 25; count; client status | head -c 400; echo ;;
down) docker stack rm $STACK ;;
demo)
  head -c 300000 /dev/urandom > /tmp/da-in.bin
  echo "== put 300KB"; client put < /tmp/da-in.bin > /tmp/da-put.json
  python3 -c 'import json;r=json.load(open("/tmp/da-put.json"));m=r["manifest"];print({k:v for k,v in r.items() if k!="manifest"});print("layers:",m["layers"]);json.dump(m,open("/tmp/da-m.json","w"))'
  M=$(cat /tmp/da-m.json)
  echo "== get + verify"; client get "$M" | cmp - /tmp/da-in.bin && echo OK
  echo "== audit (30 samples)"; client audit "$M" 30; echo
  echo "== kill region-b entirely"; docker service scale ${STACK}_node-b=0 >/dev/null; sleep 16
  client status | python3 -c 'import sys,json;print("peers visible:",json.load(sys.stdin)["peers"])'
  echo "== get again"; client get "$M" | cmp - /tmp/da-in.bin && echo "OK (recovered from remaining shards)" || echo "UNAVAILABLE"
  docker service scale ${STACK}_node-b=4 >/dev/null ;;
esac
