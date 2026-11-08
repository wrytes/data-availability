#!/usr/bin/env bash
# Usage: scripts/demo.sh up | demo | big | persist | repair | onion | hidden | edge | down
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
putfile() { client put ${2:-} < "$1" > /tmp/da-put.json
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
  for s in node-a node-b bridge hidden edge; do docker service update --force --detach ${STACK}_$s >/dev/null 2>&1 || true; done
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
hidden)
  H=$(docker ps -qf name=${STACK}_hidden | head -1)
  SID=$(docker exec "$H" da status | python3 -c 'import sys,json;print(json.load(sys.stdin)["sid"])')
  echo "== hidden holder service id: $SID"
  head -c 60000 /dev/urandom > /tmp/da-in.bin
  echo "== put with the hidden holder as an extra replica (every shard goes through a rendezvous point)"
  putfile /tmp/da-in.bin "$SID"
  echo -n "  shards held by the hidden node: "; docker exec "$H" da status | python3 -c 'import sys,json;print(json.load(sys.stdin)["shards"])'
  echo "== is it listed by anyone? (peer tables of all other nodes vs. the hidden node's addresses)"
  IPS=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$H")
  for c in $(docker ps -qf name=${STACK}_ | grep -v "^$H"); do docker exec "$c" da status; echo; done | IPS="$IPS" python3 -c '
import sys,json,os
ips=set(os.environ["IPS"].split()); seen=0; nodes=0
for l in sys.stdin:
    l=l.strip()
    if not l: continue
    nodes+=1
    for p in json.loads(l)["peer_list"]:
        if p["addr"].rsplit(":",1)[0] in ips: seen+=1
print(f"  hidden node addresses {sorted(ips)}: found in {seen} peer-table entries across {nodes} nodes")'
  echo "== direct request to the hidden node (should time out)"
  HIP=$(echo $IPS | awk '{print $1}')
  docker exec "$(docker ps -qf name=${STACK}_bridge | head -1)" sh -c "echo test | timeout 3 nc -u -w2 $HIP 7000 || echo '  no answer'"
  echo "== get using ONLY the hidden holder"
  client get - hidden < /tmp/da-m.json | cmp - /tmp/da-in.bin && echo "  OK: byte-identical" ;;
edge)
  E=$(docker ps -qf name=${STACK}_edge | head -1)
  ec() { docker exec -i "$E" da "$@"; }
  echo "== the attached client (behind a simulated NAT)"
  ec status | python3 -c 'import sys,json;j=json.load(sys.stdin);print("  guards:",[p["addr"] for p in j["peer_list"]],"| dropped by NAT filter so far:",j["nat_dropped"])'
  head -c 100000 /dev/urandom > /tmp/da-in.bin
  echo "== put + get through its three guards only"
  ec put < /tmp/da-in.bin > /tmp/da-put.json
  python3 -c 'import json;r=json.load(open("/tmp/da-put.json"));json.dump(r["manifest"],open("/tmp/da-m.json","w"));print("  stored",r["shards"],"shards,",r["replica_acks"],"replica acks")'
  ec get - < /tmp/da-m.json | cmp - /tmp/da-in.bin && echo "  OK: byte-identical (read by the edge node)"
  echo "== a public node reads what the attached node stored"
  check /tmp/da-in.bin
  echo "== is the attached node visible?"
  EIPS=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$E")
  for c in $(docker ps -qf name=${STACK}_ | grep -v "^$E"); do docker exec "$c" da status; echo; done | EIPS="$EIPS" python3 -c '
import sys,json,os
ips=set(os.environ["EIPS"].split()); seen=0; links=0; nodes=0
for l in sys.stdin:
    l=l.strip()
    if not l: continue
    j=json.loads(l); nodes+=1; links+=j["links"]
    seen+=sum(1 for p in j["peer_list"] if p["addr"].rsplit(":",1)[0] in ips)
print(f"  listed in {seen} peer tables of {nodes} nodes; guards hold {links} links to it")'
  ec status | python3 -c 'import sys,json;print("  packets the NAT filter dropped during all this:",json.load(sys.stdin)["nat_dropped"])' ;;
esac
