#!/bin/bash
# Setup script for TogetherSG on Google Compute Engine (Ubuntu/Debian)

# Update system packages
sudo apt-get update
sudo apt-get upgrade -y

# Install Python and Pip
sudo apt-get install -y python3 python3-pip python3-venv git nginx

# Create a virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate virtual environment and install dependencies
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Ensure the app.db file exists (it will be initialized by the app)
# But we might want to copy the local one if preferred.
# For now, we'll let the app initialize it if it's a fresh deploy.

echo "Setup complete! Please configure your .env file."
