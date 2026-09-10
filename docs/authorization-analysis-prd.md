# Product Requirements Document: Boolean Authorization Analyzer

**Status:** Implementation-ready draft  
**Working name:** `authz-analyzer` (replace before public launch)  
**Audience:** Maintainers and contributors building the initial OSS release

## 1. Summary

`authz-analyzer` is an open-source library and CLI for reasoning about the **effective conditions under which access is granted** in bespoke or organically grown authorization systems.

The project does not parse application source, discover policies, or impose a principal/action/resource model. Integrators translate their own effective authorization logic into a small Boolean IR. The analyzer then answers system-independent questions such as:

- Can access occur without a required permission?
- Did a change widen or narrow access?
- What minimal conditions are sufficient for access or a bypass?
- Which legacy predicates and exceptional paths explain current behavior?

The public abstraction is Boolean expressions, constraints, queries, and human-readable results. A reduced ordered binary decision diagram (ROBDD/BDD) is the initial semantic engine. A zero-suppressed decision diagram (ZDD) may later represent large families of minimal explanations compactly; neither data structure should leak into ordinary user APIs.

## 2. Problem and product thesis

Authorization in mature systems is often distributed across middleware, services, configuration, flags, group membership, overrides, and historical exceptions. Engineers can usually extract the final allow condition, but they lack a reliable way to compare or prove properties of that condition.

The product thesis is:

> If an integration can reduce effective authorization to Boolean predicates, the analyzer can provide exact, architecture-independent reasoning about their composition.

Atoms are opaque propositions such as `PII_READ`, `IS_EMPLOYEE`, or `SUPPORT_OVERRIDE`. Their meaning remains owned by the integration. Relationships that matter to reasoning must be supplied as Boolean assumptions, for example `SUPER_ADMIN -> ADMIN`.

## 3. Goals

1. Accept the same Boolean model through a string syntax, a typed programmatic AST, and a language-neutral JSON AST.
2. Prove whether effective access implies a required condition and return a small counterexample when it does not.
3. Classify semantic changes as equivalent, widened, narrowed, or incomparable and return examples of added and/or removed access.
4. Produce minimal, inspectable explanations for access and bypass conditions.
5. Support authorization archaeology through atom metadata, source provenance, deterministic output, and batch analysis.
6. Be trustworthy through precise semantics, exact Boolean reasoning, stable serialization, and extensive differential/property testing.
7. Be usable on ordinary application policies without pursuing research-grade performance in the first release.

## 4. Non-goals

- Discovering or extracting authorization logic from arbitrary source code.
- Evaluating live requests or replacing an application's policy decision point.
- Defining users, roles, groups, principals, actions, resources, effects, or policy-combining rules.
- Understanding what an atom means beyond user-supplied metadata and constraints.
- Typed predicates over strings, numbers, sets, relationships, or time.
- SMT integration in the initial release.
- Proving the source-to-IR extractor correct.
- Becoming a policy language, enforcement framework, IAM product, or general theorem prover.
- Guaranteeing compact BDDs for every Boolean function or enumerating exponentially large result sets without limits.

## 5. Personas and jobs

### Authorization/platform engineer

Normalizes scattered checks into effective-access expressions, verifies invariants across many endpoints or fields, and blocks regressions in CI.

### Service/application engineer

Compares a proposed policy with production behavior and needs actionable examples when access changes.

### Security or compliance engineer

Asks whether protected operations require mandated permissions and needs reproducible evidence for failures.

### Maintainer performing authorization archaeology

Needs to understand which checks, overrides, and source locations can enable access, including paths whose original ownership is unclear.

## 6. Core user experience

### CLI

```console
$ authz verify \
    --access '(EMPLOYEE & PII_READ) | ADMIN | SUPPORT_OVERRIDE' \
    --requires 'PII_READ | ADMIN' \
    --assume 'ADMIN -> EMPLOYEE'

FAIL: access does not imply the requirement
counterexample: EMPLOYEE=true, SUPPORT_OVERRIDE=true, PII_READ=false, ADMIN=false
minimal bypass explanation: SUPPORT_OVERRIDE & !PII_READ & !ADMIN
```

```console
$ authz diff --old old.json --new new.json

WIDENED
added-access example: SUPPORT_OVERRIDE=true, INCIDENT_OPEN=true
removed-access example: none
```

```console
$ authz explain policy.json --expression user.ssn --kind access --limit 10

1. ADMIN
2. EMPLOYEE & PII_READ
3. SUPPORT_OVERRIDE & INCIDENT_OPEN
```

All commands support `--format text|json`. Machine-readable output has a versioned schema, stable classification names, stable exit codes, and no ANSI formatting unless explicitly requested.

Recommended exit codes: `0` property holds/no semantic change requested; `1` property fails or diff is non-equivalent; `2` invalid input/resource limit/internal failure. A later flag may allow callers to select which diff classifications fail CI.

### Programmatic API (illustrative Python surface)

```python
from authz_analyzer import Analyzer, Atom, all_of, any_of

access = any_of(
    all_of(Atom("EMPLOYEE"), Atom("PII_READ")),
    Atom("ADMIN"),
)
required = any_of(Atom("PII_READ"), Atom("ADMIN"))

result = Analyzer(assumptions=["ADMIN -> EMPLOYEE"]).verify(
    access=access,
    required=required,
)

assert result.holds
```

The typed AST is immutable. Constructors validate arity and names, while the analyzer owns normalization and compilation. Public result objects contain domain terms (`classification`, `counterexample`, `explanations`), not BDD node handles.

### File-oriented workflow

```json
{
  "irVersion": "1",
  "atoms": {
    "PII_READ": {
      "description": "Caller has the PII read permission",
      "category": "permission",
      "provenance": [{"source": "permissions.py", "line": 42}]
    },
    "ADMIN": {
      "description": "Caller is an administrator",
      "provenance": [{"source": "roles.yaml", "pointer": "/roles/admin"}]
    }
  },
  "expressions": {
    "user.ssn": {
      "op": "or",
      "args": [
        {
          "op": "and",
          "args": [{"atom": "EMPLOYEE"}, {"atom": "PII_READ"}]
        },
        {"atom": "ADMIN"}
      ]
    }
  },
  "requirements": {
    "user.ssn": {
      "op": "or",
      "args": [{"atom": "PII_READ"}, {"atom": "ADMIN"}]
    }
  },
  "assumptions": [
    {
      "op": "implies",
      "left": {"atom": "ADMIN"},
      "right": {"atom": "EMPLOYEE"}
    }
  ]
}
```

Metadata is descriptive only and cannot alter semantics. Unknown metadata fields should be preserved by load/save operations where practical, or rejected in strict mode; they must never silently affect analysis.

## 7. Boolean IR contract

### Semantic nodes

| Node | JSON form | Arity | Meaning |
|---|---|---:|---|
| Constant | `{"const": true}` | 0 | Boolean constant |
| Atom | `{"atom": "NAME"}` | 0 | Opaque Boolean predicate |
| Not | `{"op":"not","arg": E}` | 1 | `¬E` |
| And | `{"op":"and","args":[...]}` | 0+ | Conjunction; empty is true |
| Or | `{"op":"or","args":[...]}` | 0+ | Disjunction; empty is false |
| Xor | `{"op":"xor","args":[...]}` | 2+ | Odd parity |
| Implies | `{"op":"implies","left":L,"right":R}` | 2 | `¬L ∨ R` |
| Equiv | `{"op":"equiv","left":L,"right":R}` | 2 | `L = R` |

The schema is closed for semantic nodes in IR v1. An IR consumer must reject unknown operators or malformed arity. JSON AST is the normative interchange representation; string and language APIs compile to the same typed AST.

### String syntax

Supported operators, highest to lowest precedence:

```text
!       not
&       and
^       xor
|       or
->      implies (right-associative)
<->     equivalence
```

Parentheses override precedence. `true` and `false` are constants. Bare atom names match `[A-Za-z_][A-Za-z0-9_.:/-]*`; other names use JSON-style quoted strings. Keyword and operator rules are documented and tested as part of the compatibility contract.

### Documents, metadata, and provenance

- `irVersion`: required string; v1 readers reject unsupported major versions.
- `atoms`: optional map from atom name to metadata.
- `expressions`: named effective-access expressions.
- `requirements`: optional named required-condition expressions.
- `assumptions`: optional list of Boolean expressions, conjoined for all analyses.
- Atom metadata v1 reserves `description`, `category`, `owner`, `tags`, and `provenance`.
- A provenance entry may contain `source`, `line`, `column`, `pointer`, `symbol`, and `note`; these locate extraction evidence but have no prescribed repository or URL semantics.

Every atom referenced anywhere is legal without a catalog entry. Duplicate JSON object keys must be rejected by compliant loaders.

## 8. Analysis semantics

Let:

- `C` be the conjunction of all assumptions (or `true` if absent),
- `A` be an effective-access expression,
- `R` be a required-condition expression,
- `O` and `N` be old and new access expressions.

An assignment is considered only when it satisfies `C`. If `C` is unsatisfiable, analysis returns `invalid_constraints`; it must not report proofs as vacuously successful without an explicit opt-in.

### Requirement verification / bypass detection

The requirement holds exactly when:

```text
C ⇒ (A ⇒ R)
```

The implementation searches for:

```text
B = C ∧ A ∧ ¬R
```

If `B` is unsatisfiable, verification passes. Otherwise it fails and returns a satisfying assignment plus a minimized explanation of `B`.

### Semantic diff

```text
Added   = C ∧ N ∧ ¬O
Removed = C ∧ O ∧ ¬N
```

| Added satisfiable | Removed satisfiable | Classification |
|---|---|---|
| no | no | `equivalent` |
| yes | no | `widened` |
| no | yes | `narrowed` |
| yes | yes | `incomparable` |

Return one deterministic, minimized counterexample for each satisfiable region. “Widened” and “narrowed” describe allowed assignments under the supplied abstraction and assumptions, not business risk.

### Counterexamples

A counterexample is a deterministic satisfying assignment. The text view may omit don't-care variables; JSON must distinguish `true`, `false`, and omitted/don't-care. Ordering follows the manager's stable variable order, then atom name as a tie-breaker.

### Minimal explanations

For target formula `Q` (access, added access, removed access, or bypass), an explanation is a consistent literal cube `E` such that:

```text
C ∧ E is satisfiable
C ∧ E ⇒ Q
```

It is **subset-minimal** when removing any literal from `E` breaks sufficiency. This is different from a merely satisfying assignment and from minimum cardinality. V1 returns a deterministic subset-minimal explanation by generalizing a witness and checking each literal for removal. It labels the result `subset-minimal`, never `minimum`.

For monotone expressions, an optional `minimal-positive` mode may return inclusion-minimal sets of true atoms. It must reject non-monotone targets rather than produce misleading results. Enumeration always requires a caller-supplied/default limit and reports truncation. Compact representation and enumeration of large explanation families are candidates for a later ZDD-backed API.

### Authorization archaeology

Batch input may contain many named expressions and requirements. Reports join every returned literal to atom metadata/provenance, identify atoms that appear in effective access but not requirements, and expose exact semantic queries without claiming that unused, redundant, or exceptional atoms are bugs. A later reachability/redundancy report may be added using existential restriction, but is not required for v1.

## 9. Architecture

```text
String parser ─┐
Typed API ─────┼─> validated typed AST ─> normalization ─> BDD compiler
JSON loader ───┘                                      │
                                                     v
                                      query layer and explainers
                                                     │
                                      text / versioned JSON results
```

### Components

1. **IR package:** immutable node types, validation, canonical JSON codec, metadata types, visitors.
2. **String parser:** tokenizer plus precedence parser with source spans and useful diagnostics.
3. **BDD engine:** one manager per analysis universe; ordered variables, unique table, computed cache, reduced nodes, complemented edges if they keep the implementation simpler and well-tested.
4. **Compiler:** compiles AST nodes and shared subexpressions into a manager; normalizes derived operators consistently.
5. **Query layer:** satisfiability, implication, equivalence, restriction, witness selection, verify, and diff.
6. **Explanation layer:** witness generalization and bounded minimal-positive enumeration.
7. **Presentation layer:** library result types, stable JSON output, CLI formatting and exit behavior.

BDD variable order materially affects size. V1 uses deterministic first-occurrence order, with an explicit order override for advanced callers. Record atom count, BDD node count, elapsed time, and applied resource limits in diagnostics. Dynamic reordering is not required initially.

ZDD is not an MVP dependency. If real workloads produce large minimal-set families, add a separate family abstraction (`count`, `take`, `minimum_cardinality`, `contains`, `restrict`) and implement it with ZDDs without changing the Boolean input or core result vocabulary.

## 10. Correctness and testing strategy

Exactness is the primary product feature.

### Unit and golden tests

- Lexer/parser precedence, associativity, quoting, spans, and malformed input.
- AST arity/type validation and lossless JSON round trips.
- BDD terminal, apply, negation, restriction, equivalence, implication, and witness operations.
- Constraints, unsatisfiable-constraint behavior, all four diff classifications, and explanation minimality.
- Stable text/JSON snapshots and exit codes.

### Exhaustive differential tests

For generated expressions up to a small atom bound (for example 2–8 atoms), compare every assignment evaluated by the AST interpreter with BDD evaluation. Independently derive verify and diff results from truth tables and compare classifications and witnesses.

### Property-based tests

- `compile(E)` agrees with direct evaluation for arbitrary assignments.
- `E == parse(print(E))` semantically.
- BDD reduction/canonicity: equivalent functions in one manager have identical roots.
- `E & true == E`, `E | false == E`, double negation, commutativity, associativity, De Morgan laws.
- Diff regions are disjoint and classification is invariant under equivalent rewrites.
- Every returned witness satisfies its advertised formula and assumptions.
- Every explanation is sufficient; removing each literal makes it insufficient.
- Minimal-positive results satisfy the target and contain no returned strict superset.

### Differential backend testing

Use a simple truth-table evaluator as an independent oracle for small models. Optionally test against a mature BDD package in development/CI, but do not make it a runtime dependency or allow shared implementation code to weaken independence.

### Fuzzing and regressions

Fuzz string and JSON parsers, persist every discovered defect as a minimal regression fixture, and test resource-limit failures as normal typed outcomes rather than crashes.

## 11. Performance and operational expectations

The target is predictable performance for application-scale policies, not benchmark leadership.

Initial targets on a current developer laptop, measured after warm-up and documented with hardware/software versions:

- Parse and analyze typical inputs of up to 1,000 atoms and 10,000 AST nodes in under 1 second when the compiled BDD remains below 100,000 nodes.
- Complete small CI checks (up to 100 atoms and 1,000 AST nodes) in under 100 ms in representative fixtures.
- Default hard limits: configurable maximum input bytes, AST nodes, atoms, BDD nodes, elapsed analysis time, and explanation count.
- On a limit, return a typed `resource_limit` error with partial diagnostics; never silently approximate.
- Keep peak memory proportional to live diagram/cache size plus output. Bound or clear computed caches between independent batch items.

These are release gates to validate with benchmarks, not universal complexity promises. Publish benchmarks for OR-of-N, overlapping DNF, nested authorization-shaped policies, parity (adversarial), and monotone CNF/minimal-set workloads.

## 12. Phased milestones

### M0 — Contract and executable skeleton

- Choose package/project name and implementation language.
- Commit this PRD, IR v1 JSON Schema, result schema, examples, and semantic decision records.
- Establish formatting, static checks, test runner, CI, and benchmark harness.

### M1 — Boolean core

- Typed AST and direct evaluator.
- JSON codec and string parser.
- BDD manager/compiler with satisfiability, implication, equivalence, restriction, and deterministic witnesses.
- Exhaustive and property-based oracle tests.

### M2 — Product queries

- Assumption validation.
- Verify/bypass and four-way semantic diff.
- Subset-minimal explanations.
- Domain result types and machine-readable errors.

### M3 — CLI and archaeology workflow

- `verify`, `diff`, `explain`, and `validate` commands.
- Batch documents, provenance-enriched output, stable JSON, exit codes, documentation, and CI examples.
- Resource limits, metrics, corpus benchmarks, and release packaging.

### M4 — Minimal families, evidence-gated

- Monotonicity check and bounded antichain-based minimal-positive enumeration.
- Minimum-cardinality/minimum-cost explanation investigation.
- Benchmark real contributed workloads; implement ZDD-backed families only if result cardinality/materialization is a demonstrated bottleneck.

### Explicitly deferred

Typed predicates/SMT, source extractors, dynamic BDD reordering, authorization-specific models, hosted service, and IDE integrations.

## 13. Recommended repository structure

```text
authz-analyzer/
├── README.md
├── LICENSE
├── pyproject.toml                 # if Python is selected
├── docs/
│   ├── semantics.md
│   ├── ir-v1.md
│   └── decisions/
├── schemas/
│   ├── boolean-ir-v1.schema.json
│   └── result-v1.schema.json
├── src/authz_analyzer/
│   ├── ir.py
│   ├── parser.py
│   ├── json_codec.py
│   ├── bdd.py
│   ├── compile.py
│   ├── queries.py
│   ├── explain.py
│   ├── results.py
│   └── cli.py
├── tests/
│   ├── fixtures/
│   ├── test_parser.py
│   ├── test_ir.py
│   ├── test_bdd.py
│   ├── test_queries.py
│   ├── test_explain.py
│   └── test_properties.py
├── examples/
│   ├── pii-access.json
│   └── policy-diff/
└── benchmarks/
    ├── corpus/
    └── bench_core.py
```

Python is a practical initial reference implementation because it lowers contribution and integration friction and supports fast property testing. The IR and schemas must remain language-neutral; language choice is an open decision until M0 closes.

## 14. Release acceptance criteria

An initial public release is acceptable when:

1. The same expression can enter through string, typed AST, or JSON and yields semantically identical results.
2. IR v1 and result v1 have published JSON Schemas and compatibility rules.
3. Assumptions constrain every query consistently; unsatisfiable assumptions produce `invalid_constraints`.
4. Verification implements `SAT(C ∧ A ∧ ¬R)` and returns a validated counterexample on failure.
5. Diff implements the exact Added/Removed formulas and passes fixtures for all four classifications.
6. Every returned counterexample is checked against the direct evaluator in tests.
7. Every claimed subset-minimal explanation passes sufficiency and literal-removal checks.
8. CLI text is useful to humans, JSON is stable for automation, and documented exit codes work.
9. Metadata/provenance appears in relevant explanations without changing semantics.
10. Exhaustive small-model differential tests and property tests pass in CI.
11. Resource limits fail explicitly without approximation or process corruption.
12. Benchmarks meet or consciously revise the targets in Section 11, with results published.
13. README includes a five-minute example, abstraction limits, threat/correctness boundaries, and a CI recipe.

## 15. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Incorrect source-to-IR translation creates false confidence | State the trust boundary prominently; offer provenance and validation tools; never claim to verify extraction. |
| Opaque atoms are treated as independent when they are not | Support assumptions in v1; show active assumptions in every report; document examples such as role hierarchy and mutual exclusion. |
| Unsatisfiable constraints make claims vacuously true | Return `invalid_constraints` by default. |
| BDD size explodes under poor order or adversarial functions | Deterministic order override, metrics, hard node/time limits, representative adversarial benchmarks. |
| “Minimal” is misunderstood | Name and define subset-minimal versus minimum-cardinality and minimal-positive; validate each claim. |
| Explanation enumeration explodes | Require limits, report truncation, keep symbolic ZDD families as an evidence-gated extension. |
| Project drifts into a new authorization language | Keep semantic IR closed and domain-neutral; require user evidence and a separate design proposal for richer predicates. |
| Homegrown BDD defects undermine trust | Independent interpreter, exhaustive truth tables, property testing, optional differential testing, and minimized regression cases. |

## 16. Open questions

Decide in M0 unless marked later:

1. Final project/package name and license.
2. Initial implementation language (recommended: Python) and minimum supported version.
3. Exact JSON result schema and whether default witness output is partial or total.
4. Stable atom ordering rules when multiple documents are analyzed together.
5. Default resource limits and CI exit policy for each diff classification.
6. Whether v1 explanation generalization uses fixed atom order only or supports caller-supplied literal costs.
7. Whether unknown metadata is preserved by default or only in a permissive mode.
8. After real-world benchmarks: whether minimal-positive families warrant a ZDD implementation.

SMT and an authorization-specific principal/action/resource model are **not** open v1 questions; they are intentionally out of scope.

## 17. Codex-friendly implementation plan

Each step should be a small reviewable change with tests and no dependency on later steps.

1. **Bootstrap:** add package skeleton, CI, test/property-test dependencies, schemas directory, and fixture conventions.
2. **Specify types:** implement immutable AST nodes, validation errors, metadata/provenance models, and direct recursive evaluation. Add exhaustive unit tests before BDD work.
3. **Implement JSON:** build strict IR v1 loader/dumper, duplicate-key detection, JSON Schema validation tests, and semantic round-trip tests.
4. **Implement strings:** build tokenizer and precedence parser with spans. Test every precedence pair, associativity case, quoted atom, and error form.
5. **Build BDD core:** implement terminals, unique table, ordered node construction, apply/cache, negation, restriction, satisfiability, and deterministic witness extraction. Compare all small functions against the direct evaluator.
6. **Compile AST:** compile every IR operator through one code path; add semantic equivalence properties and node/resource accounting.
7. **Add constraints and queries:** reject unsatisfiable `C`; implement verify and diff directly from the formulas in Section 8; validate returned witnesses independently.
8. **Add explanations:** generalize witnesses to subset-minimal sufficient cubes using implication checks; verify sufficiency and removal-minimality in code and tests.
9. **Expose public API:** freeze result/error vocabulary, prevent BDD handles from escaping, and document thread-safety/manager lifetime.
10. **Ship CLI:** implement `validate`, `verify`, `diff`, and `explain`; add text/JSON golden tests, exit-code tests, and end-to-end fixtures.
11. **Harden:** add fuzz targets, configurable limits, diagnostics, corpus benchmarks, documentation, and release automation.
12. **Evaluate minimal families:** first implement bounded antichain DP for monotone targets. Measure realistic result families before deciding whether ZDD complexity is justified.

For every implementation task, Codex should read `docs/semantics.md` and the relevant schema first, add or update the independent-oracle test before optimizing, run focused tests during development, then run the full suite and benchmark smoke tests before marking the task complete.

## 18. Product boundary in one sentence

The user tells the project **when access is effectively allowed** as Boolean logic; the project exactly analyzes that logic without needing to understand **how the user's authorization system is built**.
