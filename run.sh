#!/bin/bash
# run.sh - Script to set up and run the Secure File System (SFS).

# 1) Create venv if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment in ./venv"
    python3 -m venv venv
fi

# 2) Activate the venv
# Depending on OS, you might need a different activation script, e.g. "source venv/bin/activate"
# On Windows (Git Bash), it might be "source venv/Scripts/activate"
# On Linux/macOS, it might be "source venv/bin/activate"

if [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "win32"* ]]; then
    source venv/Scripts/activate
else
    source venv/bin/activate
fi

# 3) Install requirements
echo "Installing required Python packages..."
pip install --upgrade pip
pip install -r requirements.txt

# 4) Dispatch based on user argument

echo "Starting single-entry SFS main script..."
python -m sfs.sfs_main
