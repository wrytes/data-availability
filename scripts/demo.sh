#!/usr/bin/env bash
# Usage: scripts/demo.sh up | demo | big | persist | repair | onion | down
set -euo pipefail
cd "$(dirname "$0")/.."
STACK=da
client() { docker exec -i "$(docker ps -qf name=${STACK}_bridge | head -1)" da "$@"; }
stats() { # nodes, copies of the last uploaded file's first segment (expected 2*shards), repair activity
  for c in $(docker ps -qf name=${STACK}_); do docker exec "$c" da status; echo; done | python3 -c '
import sys,json
try: root=json.load(open("/tmp/da-m.json"))["segs"][0]["root"][:8]
except Exception: root=None
n=cp=p=r=0
for l in sys.stdin:
    l=l.strip()
    if not l: continue
    j=json.loads(l); n+=1; cp+=j["roots"].get(root,0); p+=j["repair_pushed"]; r+=j["repair_rebuilds"]
print(f"nodes={n} copies_of_file={cp} (repair: pushed={p} erasure_rebuilds={r})")'
}
putfile() { client put < "$1" > /tmp/da-put.json
  python3 - <<'PY'
import json
r=json.load(open("/tmp/da-put.json")); m=r["manifest"]
print({k:v for k,v in r.items() if k!="manifest"}); print("layers:",m["layers"])
json.dump(m,open("/tmp/da-m.json","w"))
PY
}
check() { client get - < /tmp/da-m.json | cmp - "$1" && echo "  OK: byte-identical" || { echo "  FAILED"; return 1; }; }
ostats() { # get_direct get_onion relayed dropped, summed over all nodes
  for c in $(docker ps -qf name=${STACK}_); do docker exec "$c" da status; echo; done | python3 -c '
import sys,json
t=[0,0,0,0]
for l in sys.stdin:
    l=l.strip()
    if not l: continue
    j=json.loads(l)
    for i,k in enumerate(["get_direct","get_onion","onion_relayed","onion_dropped"]): t[i]+=j[k]
print(*t)'
}
wait_peers() { sleep "${1:-20}"; }

case "${1:-demo}" in
up)
  docker build -t da:dev .
  docker stack deploy --resolve-image never -c stack.yml $STACK
  # same tag, new image content: force a rollout so swarm replaces the containers
  for s in node-a node-b bridge; do docker service update --force --detach ${STACK}_$s >/dev/null; done
  echo "waiting for rollout + gossip..."; sleep 75; docker service ls --filter name=${STACK}_ --format '{{.Name}} {{.Replicas}}'; stats ;;
down) docker stack rm $STACK ;;
demo)
  head -c 300000 /dev/urandom > /tmp/da-in.bin
  echo "== put 300KB"; putfile /tmp/da-in.bin
  echo "== get + verify"; check /tmp/da-in.bin
  echo "== audit (30 samples per segment)"; client audit - 30 < /tmp/da-m.json; echo ;;
big)
  head -c 40000000 /dev/urandom > /tmp/da-big.bin
  echo "== put 40MB (more than one 16 MiB segment)"; time putfile /tmp/da-big.bin
  echo "== get + verify"; time check /tmp/da-big.bin
  echo "== audit"; client audit - 20 < /tmp/da-m.json; echo ;;
persist)
  head -c 300000 /dev/urandom > /tmp/da-in.bin
  echo "== put"; putfile /tmp/da-in.bin; stats
  echo "== restart EVERY node (whole network down for a moment)"
  for s in node-a node-b bridge; do docker service update --force --detach ${STACK}_$s >/dev/null; done
  sleep 45; stats
  echo "== get after full restart"; check /tmp/da-in.bin ;;
repair)
  head -c 300000 /dev/urandom > /tmp/da-in.bin
  echo "== put"; putfile /tmp/da-in.bin; echo -n "  "; stats
  echo "== kill region B"; docker service scale --detach ${STACK}_node-b=0 >/dev/null; sleep 20
  echo -n "  right after: "; stats
  echo "== wait for repair"; sleep 50; echo -n "  after repair: "; stats
  echo "== now also drop two region-A nodes"; docker service scale --detach ${STACK}_node-a=2 >/dev/null; sleep 20; echo -n "  "; stats
  echo "== get"; check /tmp/da-in.bin
  docker service scale --detach ${STACK}_node-a=4 ${STACK}_node-b=4 >/dev/null ;;
onion)
  head -c 300000 /dev/urandom > /tmp/da-in.bin
  read d0 o0 r0 x0 <<< "$(ostats)"
  echo "== put + get (client requests go through 2 relays each)"; putfile /tmp/da-in.bin; check /tmp/da-in.bin
  read d1 o1 r1 x1 <<< "$(ostats)"
  echo "  GET requests served directly (holder saw the requester): $((d1-d0))"
  echo "  GET requests served over onion routes (holder saw only a relay): $((o1-o0))"
  echo "  onion packets relayed: $((r1-r0)), dropped (bad mac / replay): $((x1-x0))" ;;
esac
