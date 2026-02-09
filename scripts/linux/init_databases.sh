#!/bin/bash
# AegisForge - Initialize Databases (Linux/Mac)
# Version 1.0

echo ""
echo "================================================"
echo "  Initializing AegisForge Databases"
echo "================================================"
echo ""

# Initialize SecureBank database
echo "[1/2] Initializing SecureBank database..."
cd backend/apps/securebank
python3 database.py
python3 seed_data.py
cd ../../..
echo "✓ SecureBank database initialized"

# Initialize ShopVuln database
echo ""
echo "[2/2] Initializing ShopVuln database..."
cd backend/apps/shopvuln
python3 database.py
python3 seed_data.py
cd ../../..
echo "✓ ShopVuln database initialized"

echo ""
echo "================================================"
echo "  Database Initialization Complete!"
echo "================================================"
echo ""
