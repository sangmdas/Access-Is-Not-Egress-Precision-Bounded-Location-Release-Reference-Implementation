.PHONY: install test examples benchmark env
install:
	python -m pip install -e '.[dev]'
test:
	pytest -q
examples:
	python scripts/generate_examples.py
benchmark:
	python scripts/benchmark.py --iterations 5000
env:
	python scripts/environment_report.py
