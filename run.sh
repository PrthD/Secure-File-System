#!/bin/bash
# run.sh - Script to set up and run the Secure File System (SFS).

# Usage:
#   ./run.sh server   # to run the old 'server' interface
#   ./run.sh client   # to run the old 'client' interface
#   ./run.sh main     # (optional) to run a single-entry sfs_main.py instead, if desired

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
if [ "$1" == "server" ]; then
    echo "Starting SFS Server (Admin Interface)..."
    python -m sfs.server.sfs_server

elif [ "$1" == "client" ]; then
    echo "Starting SFS Client (User Interface)..."
    python -m sfs.client.sfs_client

elif [ "$1" == "main" ]; then
    # If you've unified everything into a single script, e.g., sfs_main.py, do:
    echo "Starting single-entry SFS main script..."
    python -m sfs.sfs_main

else
    echo "Usage: ./run.sh [server|client|main]"
    exit 1
fi
