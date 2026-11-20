.PHONY: test benchmark run coverage lint typecheck

test:
	python3 -m unittest discover -s tests -v

benchmark:
	python3 scripts/benchmark.py

run:
	python3 -m src.server

coverage:
	python3 -m coverage run -m unittest discover -s tests && python3 -m coverage report -m

lint:
	ruff check src tests scripts

typecheck:
	mypy src tests scripts
