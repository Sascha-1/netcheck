#!/bin/bash
# Netcheck Cleanup Script
# Removes generated cache and temporary files

echo "🧹 Cleaning up netcheck directory..."
echo

# Remove Python cache directories
echo "Removing __pycache__ directories..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
echo "✅ Removed __pycache__"

# Remove pytest cache
if [ -d ".pytest_cache" ]; then
    echo "Removing .pytest_cache..."
    rm -rf .pytest_cache
    echo "✅ Removed .pytest_cache"
fi

# Remove mypy cache
if [ -d ".mypy_cache" ]; then
    echo "Removing .mypy_cache..."
    rm -rf .mypy_cache
    echo "✅ Removed .mypy_cache"
fi

# Remove coverage files
if [ -f ".coverage" ]; then
    echo "Removing coverage files..."
    rm -f .coverage .coverage.*
    echo "✅ Removed coverage files"
fi

if [ -d "htmlcov" ]; then
    echo "Removing htmlcov..."
    rm -rf htmlcov
    echo "✅ Removed htmlcov"
fi

# Remove any *.pyc files
echo "Removing *.pyc files..."
find . -name "*.pyc" -delete 2>/dev/null
echo "✅ Removed *.pyc files"

# Optional: Remove log files (commented out by default)
# echo "Removing log files..."
# rm -f logs/*.txt logs/*.log
# echo "✅ Removed log files"

echo
echo "✨ Cleanup complete!"
echo
echo "All cache directories have been removed."
echo "They will regenerate automatically when needed."
echo
echo "Your repository is now clean and ready for commit."
