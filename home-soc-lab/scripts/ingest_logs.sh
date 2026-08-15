#!/usr/bin/env bash
# Bulk-ingests sample-logs/events.ndjson into Elasticsearch.
# Run this after `docker compose up -d` and after generating logs
# with generate_sample_logs.py.
#
# Usage: ./scripts/ingest_logs.sh [path-to-ndjson]

set -euo pipefail

ES_URL="${ES_URL:-http://localhost:9200}"
INDEX="soc-lab-events"
INPUT_FILE="${1:-sample-logs/events.ndjson}"

if [ ! -f "$INPUT_FILE" ]; then
  echo "Input file not found: $INPUT_FILE"
  echo "Generate it first: python3 scripts/generate_sample_logs.py --out $INPUT_FILE"
  exit 1
fi

echo "Waiting for Elasticsearch at $ES_URL ..."
until curl -s "$ES_URL" > /dev/null; do
  sleep 2
done
echo "Elasticsearch is up."

BULK_FILE=$(mktemp)
trap 'rm -f "$BULK_FILE"' EXIT

while IFS= read -r line; do
  echo "{\"index\":{\"_index\":\"$INDEX\"}}" >> "$BULK_FILE"
  echo "$line" >> "$BULK_FILE"
done < "$INPUT_FILE"

echo "Ingesting into index '$INDEX' ..."
curl -s -H "Content-Type: application/x-ndjson" \
  -X POST "$ES_URL/_bulk" \
  --data-binary "@$BULK_FILE" \
  | grep -o '"errors":[a-z]*'

COUNT=$(curl -s "$ES_URL/$INDEX/_count" | grep -o '"count":[0-9]*' | grep -o '[0-9]*')
echo "Done. $COUNT documents now in index '$INDEX'."
echo "Open Kibana at http://localhost:5601 and create a data view for '$INDEX*' to explore."
