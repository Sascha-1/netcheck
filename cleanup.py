#!/usr/bin/env python3
"""
Netcheck Cleanup Script

Removes generated cache and temporary files.

"""

import shutil
import sys
from pathlib import Path


def remove_directory(path: Path, description: str) -> None:
    """Remove a directory if it exists."""
    if path.exists():
        print(f"Removing {description}...")
        shutil.rmtree(path)
        print(f"✅ Removed {description}")


def remove_file(path: Path, description: str) -> None:
    """Remove a file if it exists."""
    if path.exists():
        print(f"Removing {description}...")
        path.unlink()
        print(f"✅ Removed {description}")


def remove_pattern(root: Path, pattern: str, description: str) -> None:
    """Remove all files/directories matching a pattern."""
    found = list(root.rglob(pattern))
    if found:
        print(f"Removing {description}...")
        for item in found:
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
        print(f"✅ Removed {len(found)} {description}")


def main() -> int:
    """Run cleanup operations."""
    print("🧹 Cleaning up netcheck directory...")
    print()
    
    # Get repository root (where this script is located)
    repo_root = Path(__file__).parent
    
    # Remove Python cache directories
    remove_pattern(repo_root, "__pycache__", "__pycache__ directories")
    
    # Remove pytest cache
    remove_directory(repo_root / ".pytest_cache", ".pytest_cache")
    
    # Remove mypy cache
    remove_directory(repo_root / ".mypy_cache", ".mypy_cache")
    
    # Remove coverage files
    remove_file(repo_root / ".coverage", "coverage database")
    remove_pattern(repo_root, ".coverage.*", "coverage data files")
    
    # Remove coverage HTML report
    remove_directory(repo_root / "htmlcov", "htmlcov")
    
    # Remove any *.pyc files
    remove_pattern(repo_root, "*.pyc", "*.pyc files")
    
    # Optional: Remove log files (commented out by default)
    # logs_dir = repo_root / "logs"
    # if logs_dir.exists():
    #     print("Removing log files...")
    #     for log_file in logs_dir.glob("*.txt"):
    #         log_file.unlink()
    #     for log_file in logs_dir.glob("*.log"):
    #         log_file.unlink()
    #     print("✅ Removed log files")
    
    print()
    print("✨ Cleanup complete!")
    print()
    print("All cache directories have been removed.")
    print("They will regenerate automatically when needed.")
    print()
    print("Your repository is now clean and ready for commit.")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
