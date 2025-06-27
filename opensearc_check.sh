#!/bin/bash

clear
echo "🛡️  OpenSearch Diagnostic Tool by Sebux"
echo "----------------------------------------"

# === SSL and Auth Prompt ===
read -p "🔐 Use HTTPS/SSL? (y/N): " USE_SSL
USE_SSL=${USE_SSL,,} # to lowercase
PROTO="http"
[ "$USE_SSL" == "y" ] && PROTO="https"

read -p "👤 Use admin authentication? (y/N): " USE_AUTH
USE_AUTH=${USE_AUTH,,}

AUTH=""
if [ "$USE_AUTH" == "y" ]; then
  read -p "OpenSearch username (default: seb): " OS_USER
  OS_USER=${OS_USER:-seb}
  read -s -p "Password for $OS_USER: " OS_PASS
  echo ""
  AUTH="-u $OS_USER:$OS_PASS"
fi

HOST="$PROTO://localhost:9200"

# === 1. Cluster Health ===
echo ""
echo "***********************************"
echo "✅ Checking cluster health"
echo "***********************************"
curl -k -s $AUTH "$HOST/_cluster/health?pretty"
read -p $'\n🔸 Press [Enter] to continue or CTRL+C to exit '

# === 2. Pipelines ===
echo ""
echo "*********************************************"
echo "✅ Checking Pipelines - Index must be created"
echo "*********************************************"
curl -k -s $AUTH "$HOST/_ingest/pipeline?pretty"
read -p $'\n🔸 Press [Enter] to continue or CTRL+C to exit '

# === 3. Index docs ===
echo ""
echo "***********************************"
echo "✅ Checking Docs Ingested (by index)"
echo "***********************************"
curl -k -s $AUTH "$HOST/_cat/indices?v&s=docs.count:desc&pretty"
read -p $'\n🔸 Press [Enter] to continue or CTRL+C to exit '

# === 4. Node Resource Usage ===
echo ""
echo "***********************************"
echo "🧠 Checking Node Resource Usage (CPU & Heap)"
echo "***********************************"
curl -k -s $AUTH "$HOST/_nodes/stats/jvm,os?pretty" | jq '.nodes[] | {
  node_name: .name,
  cpu_load: .os.cpu.load_average,
  heap_used_MB: (.jvm.mem.heap_used_in_bytes / 1024 / 1024 | floor),
  heap_max_MB: (.jvm.mem.heap_max_in_bytes / 1024 / 1024 | floor)
}'
read -p $'\n🔸 Press [Enter] to exit '

echo ""
echo "✅ Done bro! OpenSearch is up and healthy."