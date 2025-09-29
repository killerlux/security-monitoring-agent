# Security Monitoring Agent - Makefile
# Provides convenient targets for development, testing, and deployment

.PHONY: help install test lint collect clean setup-ci ci-dry-run deploy

# Configuration
PYTHON := python3
PIP := pip3
PROJECT_ROOT := $(shell pwd)
STATE_DIR := $(or $(STATE_DIR),./test-output)
CONFIG_FILE := config/policies.yaml

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

# Default target
help: ## Show this help message
	@echo "$(BLUE)Security Monitoring Agent - Available Targets$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

# Development targets
setup: ## Set up development environment
	@echo "$(BLUE)Setting up development environment...$(NC)"
	@mkdir -p $(STATE_DIR)
	@mkdir -p /var/log
	@chmod +x scripts/*.sh
	@echo "$(GREEN)Development environment ready$(NC)"

install: ## Install dependencies and system requirements
	@echo "$(BLUE)Installing system dependencies...$(NC)"
	@sudo apt-get update || true
	@sudo apt-get install -y python3 python3-pip python3-yaml ss-utils systemd iproute2 procps curl || true
	@echo "$(GREEN)System dependencies installed$(NC)"

collect: ## Run a single monitoring collection
	@echo "$(BLUE)Running monitoring collection...$(NC)"
	@$(PYTHON) -m agent --collect --output $(STATE_DIR) --config $(CONFIG_FILE)
	@echo "$(GREEN)Collection completed$(NC)"

test: ## Run tests and validation
	@echo "$(BLUE)Running tests...$(NC)"
	@$(PYTHON) -m agent --test --output $(STATE_DIR)
	@$(PYTHON) -m agent --schema
	@$(PYTHON) -m agent --example --output $(STATE_DIR)
	@echo "$(GREEN)Tests completed$(NC)"

lint: ## Run linting and code quality checks
	@echo "$(BLUE)Running linting checks...$(NC)"
	@$(PYTHON) -m py_compile agent/**/*.py || true
	@$(PYTHON) -c "import yaml; yaml.safe_load(open('$(CONFIG_FILE)'))" || echo "$(YELLOW)Config validation failed$(NC)"
	@echo "$(GREEN)Linting completed$(NC)"

# CI/CD targets
ci-dry-run: ## Run CI pipeline locally
	@echo "$(BLUE)Running CI pipeline locally...$(NC)"
	@$(MAKE) setup
	@$(MAKE) install
	@$(MAKE) lint
	@$(MAKE) test
	@$(MAKE) collect
	@echo "$(GREEN)CI pipeline completed successfully$(NC)"

# Deployment targets
deploy: ## Deploy monitoring agent
	@echo "$(BLUE)Deploying monitoring agent...$(NC)"
	@sudo mkdir -p $(STATE_DIR)
	@sudo mkdir -p /var/log
	@sudo chown -R root:root $(PROJECT_ROOT)
	@sudo chmod +x scripts/*.sh
	@echo "$(GREEN)Deployment completed$(NC)"

install-cron: ## Install cron job for automated monitoring
	@echo "$(BLUE)Installing cron job...$(NC)"
	@sudo ./scripts/install_cron.sh
	@echo "$(GREEN)Cron job installed$(NC)"

remove-cron: ## Remove cron job
	@echo "$(BLUE)Removing cron job...$(NC)"
	@sudo ./scripts/install_cron.sh --remove
	@echo "$(GREEN)Cron job removed$(NC)"

# Utility targets
clean: ## Clean up temporary files and logs
	@echo "$(BLUE)Cleaning up...$(NC)"
	@rm -f agent/models/*.json
	@rm -f $(STATE_DIR)/monitoring-*.json
	@rm -f /var/log/security-monitor*.log
	@echo "$(GREEN)Cleanup completed$(NC)"

status: ## Show monitoring agent status
	@echo "$(BLUE)Monitoring Agent Status$(NC)"
	@echo "=========================="
	@echo "State directory: $(STATE_DIR)"
	@ls -la $(STATE_DIR) 2>/dev/null || echo "State directory not found"
	@echo ""
	@echo "Cron jobs:"
	@sudo crontab -l 2>/dev/null | grep security-monitor || echo "No cron jobs found"
	@echo ""
	@echo "Recent logs:"
	@tail -5 /var/log/security-monitor.log 2>/dev/null || echo "No logs found"

logs: ## Show recent monitoring logs
	@echo "$(BLUE)Recent monitoring logs:$(NC)"
	@tail -20 /var/log/security-monitor.log 2>/dev/null || echo "No logs found"

# AppSec targets
appsec-check: ## Run AppSec checks
	@echo "$(BLUE)Running AppSec checks...$(NC)"
	@$(PYTHON) -c "from agent.appsec.collector import AppSecCollector; c = AppSecCollector(); print(c.collect())"
	@echo "$(GREEN)AppSec checks completed$(NC)"

sbom-generate: ## Generate SBOM
	@echo "$(BLUE)Generating SBOM...$(NC)"
	@$(PYTHON) -c "from agent.appsec.sbom_generator import SBOMGenerator; g = SBOMGenerator(); print(g.generate_sbom())"
	@echo "$(GREEN)SBOM generation completed$(NC)"

policy-check: ## Check policy configuration
	@echo "$(BLUE)Checking policy configuration...$(NC)"
	@$(PYTHON) -c "from agent.appsec.policy_engine import PolicyEngine; p = PolicyEngine(); print(p.evaluate_policies())"
	@echo "$(GREEN)Policy check completed$(NC)"

# Development helpers
dev-setup: setup install ## Complete development setup
	@echo "$(GREEN)Development setup completed$(NC)"

quick-test: ## Quick test run
	@echo "$(BLUE)Running quick test...$(NC)"
	@$(PYTHON) -m agent --example --output $(STATE_DIR)
	@echo "$(GREEN)Quick test completed$(NC)"

validate-config: ## Validate configuration files
	@echo "$(BLUE)Validating configuration...$(NC)"
	@$(PYTHON) -c "import yaml; yaml.safe_load(open('$(CONFIG_FILE)'))" && echo "$(GREEN)Config valid$(NC)" || echo "$(RED)Config invalid$(NC)"

# Monitoring targets
monitor-once: collect ## Alias for collect
monitor-daemon: ## Run monitoring in daemon mode
	@echo "$(BLUE)Starting monitoring daemon...$(NC)"
	@./scripts/run.sh --daemon

# System information
info: ## Show system information
	@echo "$(BLUE)System Information$(NC)"
	@echo "====================="
	@echo "OS: $$(uname -a)"
	@echo "Python: $$($(PYTHON) --version)"
	@echo "Project: $(PROJECT_ROOT)"
	@echo "State dir: $(STATE_DIR)"
	@echo "Config: $(CONFIG_FILE)"
	@echo ""
	@echo "Available commands:"
	@ss -tlnp 2>/dev/null | head -5 || echo "ss command not available"
	@systemctl --version 2>/dev/null | head -1 || echo "systemctl not available"

# Emergency targets
emergency-stop: ## Stop all monitoring (emergency)
	@echo "$(RED)Emergency stop - removing cron jobs...$(NC)"
	@sudo ./scripts/install_cron.sh --remove
	@sudo pkill -f "security-monitor" || true
	@echo "$(YELLOW)Monitoring stopped$(NC)"

emergency-clean: ## Emergency cleanup (removes all data)
	@echo "$(RED)Emergency cleanup - removing all data...$(NC)"
	@sudo rm -rf $(STATE_DIR)
	@sudo rm -f /var/log/security-monitor*.log
	@sudo ./scripts/install_cron.sh --remove
	@echo "$(YELLOW)Emergency cleanup completed$(NC)"

# Help for specific targets
help-collect: ## Show help for collection
	@echo "$(BLUE)Collection Help$(NC)"
	@echo "=================="
	@echo "make collect        - Run single collection"
	@echo "make monitor-daemon - Run continuous monitoring"
	@echo "make status         - Show current status"
	@echo "make logs           - Show recent logs"

help-appsec: ## Show help for AppSec
	@echo "$(BLUE)AppSec Help$(NC)"
	@echo "============"
	@echo "make appsec-check   - Run AppSec checks"
	@echo "make sbom-generate  - Generate SBOM"
	@echo "make policy-check   - Check policies"

# Default target when no argument is provided
.DEFAULT_GOAL := help
