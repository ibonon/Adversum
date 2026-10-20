# ==============================================================================
# Adversum — Developer Makefile
# Usage: make <target>
# ==============================================================================

.DEFAULT_GOAL := help
SHELL := /bin/bash
PYTHON := python
PIP := pip
NODE := node
NPM := npm

.PHONY: help install install-dev dev test test-fast test-cov lint lint-fix build \
        docker-build docker-up docker-down clean format check-all

help: ## Show this help message
	@echo "Adversum — Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install all dependencies (Python + Node)
	$(PIP) install -r requirements.txt
	cd frontend && $(NPM) ci

install-dev: install ## Install with dev extras
	$(PIP) install ruff pytest-cov prometheus-client pip-audit

dev: ## Start development servers (backend + frontend concurrently)
	@echo "Starting Adversum development stack..."
	@$(PYTHON) -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000 &
	@cd frontend && $(NPM) run dev

test: ## Run full test suite
	@export NEBIUS_MOCK=1 API_KEY=adv-dev-key-123 && \
		$(PYTHON) -m pytest tests/ -v --tb=short

test-fast: ## Run tests excluding slow integration tests
	@export NEBIUS_MOCK=1 API_KEY=adv-dev-key-123 && \
		$(PYTHON) -m pytest tests/ -v --tb=short -m "not slow"

test-cov: ## Run tests with coverage report
	@export NEBIUS_MOCK=1 API_KEY=adv-dev-key-123 && \
		$(PYTHON) -m pytest tests/ \
			--cov=api --cov=orchestrator --cov=modules \
			--cov-report=term-missing \
			--cov-report=html:.coverage_html \
			--cov-fail-under=50

lint: ## Run all linters
	@ruff check --select=E9,F63,F7,F82 .
	@ruff check . --ignore=E501 --exit-zero
	@cd frontend && $(NPM) run lint

lint-fix: ## Auto-fix linting issues
	@ruff check . --fix --ignore=E501
	@cd frontend && $(NPM) run lint -- --fix

format: ## Format Python code with ruff
	@ruff format .

build: ## Build frontend for production
	@cd frontend && $(NPM) run build

rust-check: ## Run Rust tests and clippy
	@cd core && cargo fmt -- --check && cargo clippy && cargo test

docker-build: ## Build all Docker images
	docker compose build

docker-up: ## Start full stack with Docker Compose
	docker compose up -d

	@echo "Waiting for services..."
	@sleep 5
	@echo "Services started:"
	@echo "  API:      http://localhost:8000"
	@echo "  Frontend: http://localhost:80"
	@echo "  Metrics:  http://localhost:8000/metrics"

docker-down: ## Stop Docker Compose stack
	docker compose down

clean: ## Remove build artifacts and caches
	@rm -rf .pytest_cache .ruff_cache __pycache__ .coverage .coverage_html
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@cd frontend && rm -rf dist node_modules/.cache

check-all: lint test build ## Run lint + test + build (full CI check)
	@echo "All checks passed!"

audit-security: ## Run security audit (pip-audit + npm audit)
	@pip-audit -r requirements.txt || true
	@cd frontend && $(NPM) audit --audit-level=high || true
