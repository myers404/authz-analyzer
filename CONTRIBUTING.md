# Contributing

Bug reports, focused fixes, tests, and documentation improvements are welcome.
Please open an issue before starting a large behavioral or API change so its
scope can be agreed first.

## Development setup

Python 3.12 or newer is required.

```console
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[test]"
```

The repository intentionally does not commit a lockfile: this is a library,
and CI tests its declared dependency ranges rather than one resolved environment.

## Checks

Run these before opening a pull request:

```console
ruff format --check .
ruff check .
mypy src/
pytest
python benchmarks/bench_core.py --size 25 --rounds 3
```

The CUDD differential tests are optional locally because they require a native
extension:

```console
DD_CUDD=1 DD_FETCH=1 python -m pip install -e ".[test,oracle]"
pytest tests/test_bdd_cudd.py tests/test_bdd_stateful_cudd.py
```

Pull requests should stay focused, include a regression test for behavioral
changes, update public documentation when behavior changes, and pass CI. Keep
commits reviewable; maintainers may squash them when merging.
