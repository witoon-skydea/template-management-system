#!/bin/bash

# Create virtual environment
python -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Initialize database
python database/init_db.py

# Create exports directory
mkdir -p exports

echo "Setup complete! You can now run the application with:"
echo "source venv/bin/activate"
echo "python app/app.py"
