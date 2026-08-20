#!/bin/sh
# Create (or rebuild) the sigmaker virtualenv.
#
# Usage:   tools/setup.sh [python-interpreter]
# Example: tools/setup.sh python3.13
#
# Defaults to python3, which on a stock Ubuntu box is the system interpreter.
# Nothing is installed into the system Python -- everything lands in ./venv.
set -e

DIR=$(readlink -f "$(dirname "$(readlink -f "$0")")/..")
PYTHON=${1:-python3}

cd "$DIR"

if ! "$PYTHON" -c 'import ensurepip' >/dev/null 2>&1; then
    echo "setup: $PYTHON cannot create virtualenvs (no ensurepip)." >&2
    echo "setup: on Ubuntu, install the matching venv package, e.g." >&2
    echo "setup:     sudo apt install $("$PYTHON" -c 'import sys; print("python%d.%d-venv" % sys.version_info[:2])')" >&2
    exit 1
fi

echo "setup: creating venv with $("$PYTHON" -V)"
rm -rf venv
"$PYTHON" -m venv venv
./venv/bin/pip install --quiet --upgrade pip setuptools wheel

# The suffix-tree fork is a separate repo nested in this one (deliberately not a
# submodule).  Prefer the local checkout so local fixes are picked up; fall back
# to GitHub when this repo was cloned without it.
if [ -d suffix-tree ]; then
    echo "setup: installing suffix-tree fork from ./suffix-tree"
    ./venv/bin/pip install --quiet ./suffix-tree
else
    echo "setup: ./suffix-tree not found, installing fork from GitHub"
    ./venv/bin/pip install --quiet 'suffix-tree @ git+https://github.com/jhumble/suffix-tree.git'
fi

./venv/bin/pip install --quiet -r requirements.txt

# Report whether the Cython extensions actually got built, rather than letting a
# silent fallback to pure Python go unnoticed.
if ./venv/bin/python -c 'import suffix_tree.node as n, sys; sys.exit(0 if n.__file__.endswith(".so") else 1)' 2>/dev/null; then
    echo "setup: OK -- suffix-tree using compiled (Cython) extensions"
else
    echo "setup: OK -- suffix-tree using pure Python (no compiler or no Cython;"
    echo "setup:      works fine, roughly 1.7x slower)"
fi

echo "setup: run it with $DIR/bin/sigmaker"
