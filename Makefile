SHELL:=/bin/bash


include makefiles/env.mk

all: help

.PHONY: help
help: ## Display this help.
help:
	@awk 'BEGIN { \
		FS = ": ##"; \
		printf "Usage:\n  make <target> [VARIABLE=value]\n\nTargets:\n" \
	} \
	/^[a-zA-Z0-9_\.\-\/%]+: ##/ { printf "  \033[32m%-15s\033[0m %s\n", $$1, $$2 }' \
	$(MAKEFILE_LIST)

.DEFAULT_GOAL := help

.PHONY: generate-token
generate-token: ## Run the token generator script
	uv run python -m src
