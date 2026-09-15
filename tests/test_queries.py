import json
from itertools import product
from pathlib import Path

import jsonschema

from authz_analyzer import (
    And,
    Atom,
    Constant,
    DiffResult,
    ErrorResult,
    Implies,
    Not,
    Or,
    VerifyResult,
    diff,
    diff_document,
    evaluate,
    load_document,
    result_to_data,
    verify,
    verify_document,
)

ROOT = Path(__file__).parent.parent


def test_verify_holds_under_assumptions():
    result = verify(
        Atom("ADMIN"),
        Atom("EMPLOYEE"),
        assumptions=(Implies(Atom("ADMIN"), Atom("EMPLOYEE")),),
    )

    assert isinstance(result, VerifyResult)
    assert result.status == "holds"
    assert result.active_assumptions == 1
    assert result.diagnostics is not None
    assert result.diagnostics.variable_order == ("ADMIN", "EMPLOYEE")


def test_verify_returns_a_complete_deterministic_counterexample():
    result = verify(
        Or((Atom("ADMIN"), Atom("SUPPORT"))),
        Atom("ADMIN"),
        access_name="user.ssn",
        required_name="user.ssn",
    )

    assert isinstance(result, VerifyResult)
    assert result.status == "violated"
    assert result.counterexample is not None
    assert result.counterexample.complete is True
    assert result.counterexample.values == {"ADMIN": False, "SUPPORT": True}


def test_verify_rejects_unsatisfiable_assumptions():
    result = verify(
        Constant(True),
        Constant(True),
        assumptions=(Atom("x"), Not(Atom("x"))),
    )

    assert isinstance(result, ErrorResult)
    assert result.status == "invalid_constraints"
    assert result.error.code == "unsatisfiable_assumptions"


def test_verify_reports_ast_and_bdd_node_limits():
    expression = And((Atom("a"), Atom("b")))

    ast_limit = verify(expression, Atom("a"), max_ast_nodes=1)
    bdd_limit = verify(expression, Atom("a"), max_bdd_nodes=1)

    assert isinstance(ast_limit, ErrorResult)
    assert ast_limit.error.code == "ast_node_limit"
    assert isinstance(bdd_limit, ErrorResult)
    assert bdd_limit.error.code == "bdd_node_limit"


def test_verify_results_match_the_published_schema():
    results = (
        verify(Atom("access"), Atom("required")),
        verify(Atom("access"), Atom("access")),
        verify(
            Constant(True),
            Constant(True),
            assumptions=(Atom("x"), Not(Atom("x"))),
        ),
    )
    schema = json.loads((ROOT / "schemas/result-v1.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)

    for result in results:
        validator.validate(result_to_data(result))


def _function(mask: int) -> Or:
    terms = []
    for index, values in enumerate(product((False, True), repeat=2)):
        if mask & (1 << index):
            terms.append(
                And(
                    tuple(
                        atom if value else Not(atom)
                        for atom, value in zip(
                            (Atom("a"), Atom("b")), values, strict=True
                        )
                    )
                )
            )
    return Or(tuple(terms))


def test_verify_matches_exhaustive_two_variable_truth_tables():
    assignments = tuple(
        dict(zip(("a", "b"), values, strict=True))
        for values in product((False, True), repeat=2)
    )
    functions = tuple(_function(mask) for mask in range(16))

    for constraints, access, required in product(functions, repeat=3):
        result = verify(access, required, assumptions=(constraints,))
        valid = [case for case in assignments if evaluate(constraints, case)]
        bypasses = [
            case
            for case in valid
            if evaluate(access, case) and not evaluate(required, case)
        ]

        if not valid:
            assert isinstance(result, ErrorResult)
            assert result.status == "invalid_constraints"
        elif bypasses:
            assert isinstance(result, VerifyResult)
            assert result.status == "violated"
            assert result.counterexample is not None
            assert result.counterexample.values in bypasses
        else:
            assert isinstance(result, VerifyResult)
            assert result.status == "holds"


def test_diff_returns_all_four_classifications():
    x, y = Atom("x"), Atom("y")
    cases = (
        (x, x, "equivalent", False, False),
        (x, Or((x, y)), "widened", True, False),
        (Or((x, y)), x, "narrowed", False, True),
        (x, y, "incomparable", True, True),
    )

    for old, new, classification, has_added, has_removed in cases:
        result = diff(old, new)
        assert isinstance(result, DiffResult)
        assert result.classification == classification
        assert (result.added_access is not None) is has_added
        assert (result.removed_access is not None) is has_removed


def test_diff_rejects_unsatisfiable_assumptions():
    result = diff(
        Constant(False),
        Constant(True),
        assumptions=(Atom("x"), Not(Atom("x"))),
    )

    assert isinstance(result, ErrorResult)
    assert result.kind == "diff"
    assert result.status == "invalid_constraints"


def test_diff_reports_the_shared_variable_limit():
    result = diff(
        Constant(False),
        Constant(True),
        variable_order=(f"x{i}" for i in range(257)),
    )

    assert isinstance(result, ErrorResult)
    assert result.kind == "diff"
    assert result.status == "resource_limit"
    assert result.error.code == "bdd_variable_limit"


def test_diff_results_match_the_published_schema():
    x, y = Atom("x"), Atom("y")
    results = (
        diff(x, x),
        diff(x, Or((x, y))),
        diff(Or((x, y)), x),
        diff(x, y),
        diff(x, y, assumptions=(x, Not(x))),
    )
    schema = json.loads((ROOT / "schemas/result-v1.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)

    for result in results:
        validator.validate(result_to_data(result))


def test_diff_matches_exhaustive_two_variable_truth_tables():
    assignments = tuple(
        dict(zip(("a", "b"), values, strict=True))
        for values in product((False, True), repeat=2)
    )
    functions = tuple(_function(mask) for mask in range(16))

    for constraints, old, new in product(functions, repeat=3):
        result = diff(old, new, assumptions=(constraints,))
        valid = [case for case in assignments if evaluate(constraints, case)]
        added = [
            case for case in valid if evaluate(new, case) and not evaluate(old, case)
        ]
        removed = [
            case for case in valid if evaluate(old, case) and not evaluate(new, case)
        ]

        if not valid:
            assert isinstance(result, ErrorResult)
            assert result.status == "invalid_constraints"
            continue

        assert isinstance(result, DiffResult)
        expected = {
            (False, False): "equivalent",
            (True, False): "widened",
            (False, True): "narrowed",
            (True, True): "incomparable",
        }[bool(added), bool(removed)]
        assert result.classification == expected
        if added:
            assert result.added_access is not None
            assert result.added_access.counterexample.values in added
        else:
            assert result.added_access is None
        if removed:
            assert result.removed_access is not None
            assert result.removed_access.counterexample.values in removed
        else:
            assert result.removed_access is None


def test_document_queries_use_named_expressions_and_assumptions():
    pii = load_document((ROOT / "examples/pii-access.json").read_bytes())
    verification = verify_document(pii, "user.ssn")
    assert isinstance(verification, VerifyResult)
    assert verification.status == "violated"
    assert verification.diagnostics is not None
    assert verification.diagnostics.ast_node_count == 14
    assert verification.diagnostics.variable_order == (
        "ADMIN",
        "EMPLOYEE",
        "PII_READ",
        "SUPPORT_OVERRIDE",
        "INCIDENT_OPEN",
    )

    policies = load_document((ROOT / "examples/policy-diff.json").read_bytes())
    comparison = diff_document(policies, "old", "new")
    assert isinstance(comparison, DiffResult)
    assert comparison.classification == "widened"


def test_document_queries_report_unknown_names():
    document = load_document((ROOT / "examples/pii-access.json").read_bytes())

    missing_access = verify_document(document, "missing")
    missing_requirement = verify_document(document, "user.ssn", "missing")
    missing_diff = diff_document(document, "user.ssn", "missing")

    assert isinstance(missing_access, ErrorResult)
    assert missing_access.error.code == "unknown_expression"
    assert isinstance(missing_requirement, ErrorResult)
    assert missing_requirement.error.code == "unknown_requirement"
    assert isinstance(missing_diff, ErrorResult)
    assert missing_diff.error.code == "unknown_expression"
