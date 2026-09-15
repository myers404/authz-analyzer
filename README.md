# authz-analyzer

`authz-analyzer` verifies and compares Boolean authorization policies. It can
prove that an access rule satisfies a requirement, find a counterexample when
it does not, and show whether a policy change grants or revokes access.

Policies are compiled to reduced ordered binary decision diagrams (BDDs), so
results are exact for the Boolean model rather than based on sampled inputs.

New to Boolean policy analysis? Start with the
[guided examples](examples/README.md), which explain expressions, assumptions,
counterexamples, and minimal explanations in plain language.

## Features

- Validate the versioned JSON policy format.
- Verify that an access rule implies a security requirement.
- Compare old and new policies for grants, revocations, or any semantic change.
- Return concrete counterexamples for failed checks.
- Enumerate complete, bounded families of subset-minimal explanations.
- Produce metadata-enriched batch verification reports.
- Use the command line or the Python API.

## Installation

Python 3.12 or newer is required. Install the project from source:

```console
git clone https://github.com/myers404/authz-analyzer.git
cd authz-analyzer
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## Command line

Validate a policy document:

```console
authz validate examples/pii-access.json
```

Verify that an access expression implies its requirement:

```console
authz verify examples/pii-access.json --access user.ssn
```

Compare two named expressions:

```console
authz diff examples/policy-diff.json --old old --new new
```

Show the installed version:

```console
authz --version
```

Enumerate the minimal ways a named expression can hold:

```console
authz explain examples/pii-access.json --expression user.ssn
```

For quick checks, expressions and assumptions can be supplied directly:

```console
authz verify --access-expr 'ADMIN' --required-expr 'EMPLOYEE' \
  --assume 'ADMIN -> EMPLOYEE'
authz diff --old-expr 'ADMIN' --new-expr 'ADMIN | SUPPORT_OVERRIDE'
authz explain --expr 'ADMIN | !SUSPENDED'
```

Repeat `--assume` to add multiple assumptions. With a JSON document, CLI
assumptions are added to the document's assumptions.

Verify every expression that has a same-named requirement:

```console
authz report examples/pii-access.json
```

All commands accept `--format text` or `--format json`. Verification uses the
requirement with the same name as the access expression unless `--required`
selects another one.

Exit codes are intended for CI and other automation:

| Code | Meaning |
| ---: | --- |
| `0` | Valid input, or the queried policies satisfy the requested check |
| `1` | A requirement is violated or the policies differ |
| `2` | Invalid input, invalid arguments, or a resource limit was reached |

## Python API

Expressions can be built with the compact string syntax or the typed expression
classes:

```python
from authz_analyzer import diff, parse, verify

access = parse('ADMIN | (EMPLOYEE & !"account suspended")')
required = parse("ADMIN | EMPLOYEE")

verification = verify(access, required)
assert verification.status == "holds"

change = diff(parse("ADMIN"), access)
assert change.classification == "widened"
assert change.added_access is not None
```

The expression language supports atoms, `!` (not), `&` (and), `|` (or), and
parentheses. Quote atom names that contain spaces or punctuation. Use
`load_document()`, `verify_document()`, and `diff_document()` when working with
the JSON format.

See the [examples](https://github.com/myers404/authz-analyzer/tree/main/examples)
for complete inputs and results. The normative formats and behavior are
documented in [Boolean IR v1](https://github.com/myers404/authz-analyzer/blob/main/docs/ir-v1.md)
and [analysis semantics](https://github.com/myers404/authz-analyzer/blob/main/docs/semantics.md).

## Scope and limits

The analyzer reasons about the Boolean formulas it receives. It does not
discover authorization logic from an application or prove that a policy model
matches the source system. Atoms are opaque and metadata does not affect
semantics.

Default limits protect callers from unexpectedly expensive inputs:

- 1 MB input documents
- 10,000 expression nodes per query
- 256 variables per BDD manager
- 100,000 BDD nodes per query
- 100,000 intermediate explanation cubes

BDD size can still grow exponentially for difficult formulas. The CLI reports
the applied variable order, size, and timing diagnostics in JSON output.

Verification and diff results include one deterministic subset-minimal
explanation for each failing region. `authz explain` returns up to 20
explanations by default and explicitly reports when more exist. Use `--limit`
to change the output count. Direct expression inputs do not include the atom
metadata available in JSON documents.

## Development

See the [contribution guide](https://github.com/myers404/authz-analyzer/blob/main/CONTRIBUTING.md)
for environment setup, project checks, and contribution guidelines.

The test suite compares the BDD implementation against exhaustive truth tables
and property-based tests. A separate optional suite compares it against CUDD.

## License

[MIT](https://github.com/myers404/authz-analyzer/blob/main/LICENSE)
