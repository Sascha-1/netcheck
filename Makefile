# Netcheck - Makefile for common development tasks
#
# Usage:
#   make test      - Run tests with coverage
#   make lint      - Run all linters
#   make format    - Auto-format code with ruff
#   make check     - Run tests + linting (CI check)
#   make clean     - Remove cache and generated files
#

.PHONY: help test lint format check clean mypy pylint ruff

# Default target
help:
	@echo "Netcheck - Development Commands"
	@echo ""
	@echo "Available targets:"
	@echo "  make test      - Run pytest with coverage"
	@echo "  make lint      - Run all linters (pylint, ruff, mypy)"
	@echo "  make format    - Auto-format code with ruff"
	@echo "  make check     - Run tests + linting (CI check)"
	@echo "  make clean     - Remove cache and generated files"
	@echo ""
	@echo "Individual linters:"
	@echo "  make pylint    - Run pylint only"
	@echo "  make ruff      - Run ruff only"
	@echo "  make mypy      - Run mypy only"

# Run tests with coverage
test:
	pytest

# Run all linters
lint:
	@echo "Running pylint..."
	pylint .
	@echo ""
	@echo "Running ruff check..."
	ruff check .
	@echo ""
	@echo "Running ruff format check..."
	ruff format --check .
	@echo ""
	@echo "Running mypy..."
	mypy
	@echo ""
	@echo "✓ All linters passed!"

# Auto-format code
format:
	ruff format .
	@echo "✓ Code formatted with ruff"

# Run full CI check (tests + linting)
check: test lint
	@echo "✓ All checks passed!"

# Clean cache and generated files
clean:
	rm -rf __pycache__
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "✓ Cleaned cache and generated files"

# Individual linters
pylint:
	pylint .

ruff:
	ruff check .
	ruff format --check .

mypy:
	mypy
