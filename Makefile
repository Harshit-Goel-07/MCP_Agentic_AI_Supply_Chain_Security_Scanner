.PHONY: install lint format typecheck test cov scan-examples docker clean

install:
	python -m pip install -e ".[dev,api,semantic]"

lint:
	ruff check .

format:
	ruff format .

typecheck:
	mypy mcpscan

test:
	pytest

cov:
	pytest --cov=mcpscan --cov-report=xml --cov-report=term-missing

scan-examples:
	mcpscan scan --targets ./examples --format table

docker:
	docker build -t mcpscan:local .

clean:
	rm -rf dist build .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml
