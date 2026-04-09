.PHONY: up down restart logs build test-p0 test-p1 test-p2 test-p3 test-p4 test-p5 sbom

up:
	docker compose up -d

down:
	docker compose down

restart: down up

logs:
	docker compose logs -f

build:
	docker compose build

test-p0:
	pytest tests/phase0/ -v

test-p1:
	pytest tests/phase1/ -v

test-p2:
	pytest tests/phase2/ -v

test-p3:
	pytest tests/phase3/ -v

test-p4:
	pytest tests/phase4/ -v

test-p5:
	pytest tests/phase5/ -v

test-all: test-p0 test-p1 test-p2 test-p3 test-p4 test-p5

sbom:
	./scripts/sbom-generate.sh

fix-perms:
	sudo chown -R archi:archi ../models_data ../runtime_data ../storage || true
