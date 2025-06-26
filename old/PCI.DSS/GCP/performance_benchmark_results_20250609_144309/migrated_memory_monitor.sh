#!/usr/bin/env bash
pid="$1"
interval="$2"
output_file="$3"

echo "timestamp,rss_kb,vsz_kb" > "$output_file"

while kill -0 "$pid" 2>/dev/null; do
    timestamp=$(date +%s.%N)
    memory_info=$(ps -o rss=,vsz= -p "$pid" 2>/dev/null)
    if [[ -n "$memory_info" ]]; then
        echo "$timestamp,$memory_info" >> "$output_file"
    fi
    sleep "$interval"
done
