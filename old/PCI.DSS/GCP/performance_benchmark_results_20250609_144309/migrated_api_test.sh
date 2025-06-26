#!/usr/bin/env bash
start_time=$(date +%s.%N)

# Simulate API calls found in script
for i in $(seq 1 5); do
    gcloud config get-value project >/dev/null 2>&1
done

end_time=$(date +%s.%N)
echo "$end_time - $start_time" | bc -l
