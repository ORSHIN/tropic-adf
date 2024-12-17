# adf

## Repo structure

* `toolkit/` contains the file to test our framework
    * `yaml` contains the AD files
    * `analyze.py` automatically analyze ADs (maps, chains, trees, ...)
    * `check.py` check syntax and semantic of the ADs
    * `parse.py` parse ADs from other sources (CAPEC, ...)
    * `*_test.py` test scripts
    * `Makefile` automate tasks

## Initialize development environment

* Run `make dev-setup`
* Use a text editor with YAML and Python support (lint, check, fix, ...)
    * E.g., VSCode, vim, ...
