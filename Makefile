# Copyright (c) 2019 SiFive Inc.
# SPDX-License-Identifier: Apache-2.0

venv/bin/activate:
	python3 -m venv venv
	source $@ && pip install --upgrade pip
	source $@ && pip install -r requirements.txt

.PHONY: virtualenv
virtualenv: venv/bin/activate

.PHONY: test-types
test-types: venv/bin/activate
	source $< && mypy -m unittest
test: test-types

.PHONY: test-lint
test-lint: venv/bin/activate
	source $< && pylint pydevicetree
test: test-lint

UNIT_TESTS = tests/test_devicetree.py \
	     tests/test_grammar.py \
	     tests/test_overlay.py

.PHONY: test-unit
test-unit: venv/bin/activate $(UNIT_TESTS)
	source $< && python3 -m unittest $(UNIT_TESTS)
test: test-unit

INTEGRATION_TESTS = tests/test_full_trees.py

.PHONY: test-integration
test-integration: venv/bin/activate
	source $< && python3 -m unittest $(INTEGRATION_TESTS)
test: test-integration

.PHONY: test
test:

.PHONY: clean
clean:
	-rm -rf venv .mypy_cache __pycache__
