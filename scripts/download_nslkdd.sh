#!/usr/bin/env bash
# Fetch the public NSL-KDD CSVs (not stored in git).
set -euo pipefail
mkdir -p data/nslkdd
for f in KDDTrain+ KDDTest+; do
  curl -fsSL -o "data/nslkdd/$f.txt" "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/${f/+/%2B}.txt"
done
wc -l data/nslkdd/*.txt
