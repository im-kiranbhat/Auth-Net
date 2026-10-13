#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
sudo mn -c
exec sudo -E python3 topology.py
