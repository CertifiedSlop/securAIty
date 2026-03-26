.PHONY: help setup dev run test test-unit test-integration test-e2e coverage lint format clean build docker-up docker-down docker-build docker-run docker-test docker-logs docker-restart docker-clean docker-health secrets-generate

help: ## Display this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

setup: ## Install dependencies and setup development environment
	@echo "Setting up securAIty development environment..."
	python3 -m venv venv
	. venv/bin/activate && pip install --upgrade pip
	. venv/bin/activate && pip install -e .
	@echo "Setup complete. Activate virtual environment with: source venv/bin/activate"

setup-dev: ## Install development dependencies
	. venv/bin/activate && pip install -r requirements-dev.txt

dev: ## Run application in development mode with hot reload
	. venv/bin/activate && python -m uvicorn src.securAIty.api.main:app --reload --host 0.0.0.0 --port 8000

run: ## Run the application
	. venv/bin/activate && python -m uvicorn src.securAIty.api.main:app --host 0.0.0.0 --port 8000

test: ## Run all tests
	. venv/bin/activate && pytest tests/ -v

test-unit: ## Run unit tests only
	. venv/bin/activate && pytest tests/unit/ -v

test-integration: ## Run integration tests only
	. venv/bin/activate && pytest tests/integration/ -v

test-e2e: ## Run end-to-end tests only
	. venv/bin/activate && pytest tests/e2e/ -v

coverage: ## Run tests with coverage report
	. venv/bin/activate && pytest tests/ --cov=src/securAIty --cov-report=html --cov-report=term-missing

coverage-xml: ## Run tests with coverage XML report (for CI)
	. venv/bin/activate && pytest tests/ --cov=src/securAIty --cov-report=xml

lint: ## Run linting checks
	. venv/bin/activate && ruff check src/securAIty tests
	. venv/bin/activate && mypy src/securAIty

format: ## Format code with ruff
	. venv/bin/activate && ruff format src/securAIty tests
	. venv/bin/activate && ruff check src/securAIty tests --fix

lint-fix: ## Format code and fix linting issues
	. venv/bin/activate && ruff format src/securAIty tests
	. venv/bin/activate && ruff check src/securAIty tests --fix

type-check: ## Run type checking with mypy
	. venv/bin/activate && mypy src/securAIty --ignore-missing-imports

clean: ## Clean up build artifacts and cache
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf .ruff_cache
	rm -rf htmlcov/
	rm -rf coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*~" -delete
	find . -type f -name "*.orig" -delete
	@echo "Clean complete"

build: ## Build the package
	. venv/bin/activate && pip install build
	python -m build

docker-up: ## Start Docker containers
	docker-compose up -d

docker-down: ## Stop Docker containers
	docker-compose down

docker-logs: ## Show Docker container logs
	docker-compose logs -f

docker-restart: ## Restart Docker containers
	docker-compose restart

docker-build: ## Build Docker images
	docker-compose build --no-cache

docker-build-prod: ## Build Docker images for production
	docker-compose build --no-cache --build-arg BUILD_TARGET=production

docker-run: ## Build and start Docker containers
	docker-compose up -d --build

docker-run-fresh: ## Remove old containers and start fresh
	docker-compose down -v
	docker-compose up -d --build

docker-test: ## Run tests inside Docker container
	docker-compose run --rm app pytest tests/ -v

docker-test-unit: ## Run unit tests inside Docker container
	docker-compose run --rm app pytest tests/unit/ -v

docker-test-integration: ## Run integration tests inside Docker container
	docker-compose run --rm app pytest tests/integration/ -v

docker-coverage: ## Run tests with coverage inside Docker container
	docker-compose run --rm app pytest tests/ --cov=src/securAIty --cov-report=html

docker-logs: ## Show Docker container logs
	docker-compose logs -f

docker-logs-app: ## Show application logs only
	docker-compose logs -f app

docker-logs-natss: ## Show NATS logs only
	docker-compose logs -f natss

docker-logs-postgres: ## Show PostgreSQL logs only
	docker-compose logs -f postgres

docker-logs-vault: ## Show Vault logs only
	docker-compose logs -f vault

docker-health: ## Check health of all containers
	docker-compose ps
	@echo ""
	@echo "Health check status:"
	@docker inspect --format='{{.Name}}: {{.State.Health.Status}}' $$(docker-compose ps -q) 2>/dev/null || echo "Health checks not available"

docker-shell: ## Open shell in running app container
	docker-compose exec app /bin/bash

docker-shell-root: ## Open shell as root in running app container
	docker-compose exec --user root app /bin/bash

docker-db-shell: ## Open psql shell in database container
	docker-compose exec postgres psql -U security_user -d security_db

docker-clean: ## Remove all Docker containers, volumes, and images
	docker-compose down -v --rmi all
	docker system prune -f

docker-network-inspect: ## Inspect Docker network
	docker network inspect securAIty_securAIty_internal

secrets-generate: ## Generate new secure secrets
	@echo "Generating new secrets..."
	@mkdir -p secrets
	@openssl rand -base64 32 > secrets/postgres_password.txt
	@echo "hvs.$$(openssl rand -hex 32)" > secrets/vault_root_token.txt
	@chmod 600 secrets/*.txt
	@echo "Secrets generated successfully. Store these securely!"

secrets-validate: ## Validate secrets exist
	@echo "Validating secrets..."
	@test -f secrets/postgres_password.txt || (echo "ERROR: postgres_password.txt not found" && exit 1)
	@test -f secrets/vault_root_token.txt || (echo "ERROR: vault_root_token.txt not found" && exit 1)
	@echo "All secrets validated"

migrate: ## Run database migrations
	. venv/bin/activate && python -m src.securAIty.storage.migrations

shell: ## Open Python shell with application context
	. venv/bin/activate && python -c "import sys; sys.path.insert(0, 'src'); from securAIty import *"

requirements: ## Update requirements.txt from pyproject.toml
	. venv/bin/activate && pip install pip-tools
	pip-compile pyproject.toml -o requirements.txt
	pip-compile pyproject.toml --extra dev -o requirements-dev.txt

security-scan: ## Run security scanning with bandit
	. venv/bin/activate && bandit -r src/securAIty -f json -o bandit-report.json

pre-commit: lint type-check test ## Run all pre-commit checks

install-hooks: ## Install pre-commit hooks
	. venv/bin/activate && pip install pre-commit
	pre-commit install
