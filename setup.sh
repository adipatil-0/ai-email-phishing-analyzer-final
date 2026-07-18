#!/usr/bin/env bash
# setup.sh — one-shot local setup for AI Email Phishing Analyzer
# Usage: chmod +x setup.sh && ./setup.sh
set -e  # stop on first error, don't silently continue on a broken setup

echo "=== AI Email Phishing Analyzer — Setup ==="

# 1. Create venv if it doesn't already exist (safe to re-run)
if [ ! -d "venv" ]; then
    echo "[1/6] Creating virtual environment..."
    python3 -m venv venv
else
    echo "[1/6] Virtual environment already exists, skipping."
fi

# 2. Activate it
echo "[2/6] Activating virtual environment..."
source venv/bin/activate

# 3. Install dependencies
echo "[3/6] Installing dependencies from requirements.txt..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# 4. Set up .env if missing — never overwrite an existing one
if [ ! -f ".env" ]; then
    echo "[4/6] No .env found — creating one from .env.example."
    cp .env.example .env

    # Auto-generate a real Flask secret key instead of leaving the placeholder
    NEW_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    # Works on both GNU sed (Linux/Kali) and BSD sed (macOS)
    sed -i.bak "s/FLASK_SECRET_KEY=.*/FLASK_SECRET_KEY=${NEW_KEY}/" .env
    rm -f .env.bak

    echo "    -> Generated a random FLASK_SECRET_KEY for you."
    echo "    -> You still need to add your VIRUSTOTAL_API_KEY manually:"
    echo "       nano .env"
else
    echo "[4/6] .env already exists, leaving it untouched."
fi

# 5. Check Ollama status (don't fail setup if it's not running — just warn)
echo "[5/6] Checking Ollama..."
if command -v ollama >/dev/null 2>&1; then
    if ollama list 2>/dev/null | grep -q "llama3.2"; then
        echo "    -> Ollama installed and llama3.2 model found."
    else
        echo "    -> Ollama installed but llama3.2 model not found."
        echo "       Run: ollama pull llama3.2:1b"
    fi
    if ! pgrep -f "ollama serve" >/dev/null 2>&1; then
        echo "    -> Ollama daemon not running. Starting it in the background..."
        nohup ollama serve > /tmp/ollama.log 2>&1 &
        sleep 2
    else
        echo "    -> Ollama daemon already running."
    fi
else
    echo "    -> Ollama not found on this machine."
    echo "       AI layer will fall back to degraded mode (heuristics + threat intel only)."
    echo "       Install from https://ollama.com if you want the full AI-enabled scoring."
fi

# 6. Launch the app
echo "[6/6] Starting Flask app..."
echo "    -> Visit http://127.0.0.1:5000 once it's up."
echo "    -> Press Ctrl+C to stop."
echo ""
python3 app.py
