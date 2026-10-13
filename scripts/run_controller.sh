#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
exec sudo -E .venv/bin/python controller/auth_controller.py
