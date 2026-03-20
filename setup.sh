#!/bin/bash
set -e

echo "Setting up Chakshu..."

# ── Python environment ────────────────────────────────────────────
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# ── Submodules ────────────────────────────────────────────────────
echo "Pulling loghub submodule..."
git submodule update --init --recursive

# ── Directory structure ───────────────────────────────────────────
mkdir -p data/raw/lanl/netflow
mkdir -p data/raw/lanl/wls
mkdir -p data/raw/cicids
mkdir -p data/processed
mkdir -p data/synthetic

# ── LANL dataset ──────────────────────────────────────────────────
echo ""
echo "LANL dataset requires manual download via browser."
echo "Opening download page..."

LANL_URL="https://csr.lanl.gov/data/2017/"

# detect OS and launch browser accordingly
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open "$LANL_URL" 2>/dev/null || sensible-browser "$LANL_URL" 2>/dev/null || \
        echo "Could not open browser. Visit manually: $LANL_URL"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    open "$LANL_URL"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    start "$LANL_URL"
else
    echo "Could not detect OS. Visit manually: $LANL_URL"
fi

echo "Once downloaded, place files in: data/raw/lanl/"

# ── CICIDS dataset ────────────────────────────────────────────────
echo ""
echo "Downloading CICIDS2017..."
kaggle datasets download -d  chethuhn/network-intrusion-dataset -p data/raw/cicids/ --unzip

# ── Done ──────────────────────────────────────────────────────────
echo ""
echo "Setup complete. Next steps:"
echo "  1. Place LANL files in:   data/raw/lanl/"
echo "  2. Place CICIDS files in: data/raw/cicids/"
echo "  3. Loghub is ready at:    data/raw/loghub/"
