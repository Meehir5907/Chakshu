$ErrorActionPreference = "Stop"

Write-Host "Setting up Chakshu..."

# ── Python environment ────────────────────────────────────────────
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# ── Submodules ────────────────────────────────────────────────────
Write-Host "Pulling loghub submodule..."
git submodule update --init --recursive

# ── Directory structure ───────────────────────────────────────────
$dirs = @(
    "data\raw\lanl\netflow",
    "data\raw\lanl\wls",
    "data\raw\cicids",
    "data\processed",
    "data\synthetic"
)
foreach ($dir in $dirs) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# ── LANL dataset ──────────────────────────────────────────────────
Write-Host ""
Write-Host "LANL dataset requires manual download via browser."
Write-Host "Opening download page..."
Start-Process "https://csr.lanl.gov/data/2017/"
Write-Host "Once downloaded, place files in: data\raw\lanl\{netflow,wls}"

# ── CICIDS dataset ────────────────────────────────────────────────
Write-Host ""
Write-Host "Downloading CICIDS2017..."
kaggle datasets download -d chethuhn/network-intrusion-dataset -p data\raw\cicids\ --unzip

# ── Done ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Setup complete. Next steps:"
Write-Host "  1. Place LANL netflow files in: data\raw\lanl\netflow\"
Write-Host "  2. Place LANL WLS files in:     data\raw\lanl\wls\"
Write-Host "  3. CICIDS files in:             data\raw\cicids\"
Write-Host "  4. Loghub is ready at:          data\raw\loghub\"
