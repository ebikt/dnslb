#!/bin/bash
set -e
cd "$(dirname "$0")"
cd ..
PYTHONPATH="./lib" mypy --config mypy/mypy.ini dnslb.py
