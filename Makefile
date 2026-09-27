SHELL := /bin/bash

.DEFAULT_GOAL := help

help: ## Liste les cibles disponibles
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk -F':.*?## ' '{printf "  \033[1m%-14s\033[0m %s\n", $$1, $$2}'

up: ## Amorce la PKI et démarre la TSA (idempotent)
	./scripts/bootstrap.sh

demo: ## Horodate un fichier et vérifie le jeton avec openssl ts
	./scripts/demo.sh

test: ## Exécute les tests du workspace
	cargo test --workspace

lint: ## Vérifie le formatage et lance clippy
	cargo fmt --check
	cargo clippy --workspace --all-targets -- -D warnings

licenses: ## Vérifie la compatibilité des licences des dépendances avec EUPL-1.2 / AGPL-3.0 (cargo-deny)
	cargo deny check licenses

provenance: ## Rapport de provenance des commits de dev depuis les sessions locales
	scripts/provenance.py report

audit: ## Vérifie la chaîne de hachage des journaux d'audit (TSA et CA)
	docker compose exec tsa tsa-server verify-audit
	docker compose exec ca ca-server verify-audit

conformance: ## Produit la matrice de conformité ETSI (échec sur écart bloquant)
	cargo run --bin ca-server -- conformance

conformance-doc: ## Régénère docs/CONFORMITE-ETSI.md depuis oe-conformance
	cargo run --bin ca-server -- conformance --markdown > docs/CONFORMITE-ETSI.md

ra: ## Liste les demandes d'enrôlement en attente de décision
	docker compose exec ca ca-server ra list PENDING

helm-lint: ## Vérifie le chart Helm (lint + rendu complet)
	helm lint deploy/helm/open-eidas
	helm template open-eidas deploy/helm/open-eidas > /dev/null
	! helm template open-eidas deploy/helm/open-eidas --set production=true --set ca.autoApprove.enabled=true > /dev/null 2>&1
	helm template open-eidas deploy/helm/open-eidas -f deploy/helm/open-eidas/ci/ra-console-values.yaml > /dev/null
	! helm template open-eidas deploy/helm/open-eidas -f deploy/helm/open-eidas/ci/ra-console-values.yaml --set ca.internal.enabled=false > /dev/null 2>&1
	diff -u crates/oe-castore/sql/ra_console_grants.sql deploy/helm/open-eidas/files/ra_console_grants.sql

logs: ## Suit les journaux de la TSA
	docker compose logs -f tsa

down: ## Arrête la pile en conservant les volumes
	docker compose down

purge: ## Arrête la pile et supprime les volumes (registre de CA et tokens HSM inclus)
	docker compose down -v

.PHONY: help up demo test lint licenses provenance audit conformance conformance-doc ra helm-lint logs down purge
