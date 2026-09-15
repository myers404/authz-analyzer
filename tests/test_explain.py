from itertools import product

from authz_analyzer import (
    And,
    Atom,
    Constant,
    ErrorResult,
    ExplainResult,
    Explanation,
    Literal,
    Not,
    Or,
    diff,
    evaluate,
    explain,
    load_document,
    parse,
    report_document,
    verify,
)


def _cubes(explanations: tuple[Explanation, ...]):
    return {
        frozenset((literal.atom, literal.value) for literal in item.literals)
        for item in explanations
    }


def test_explain_enumerates_every_prime_implicant_including_consensus():
    result = explain(parse("(a & b) | (!a & c) | (b & c)"))

    assert isinstance(result, ExplainResult)
    assert result.truncated is False
    assert _cubes(result.explanations) == {
        frozenset({("a", False), ("c", True)}),
        frozenset({("a", True), ("b", True)}),
        frozenset({("b", True), ("c", True)}),
    }


def test_explain_treats_assumptions_as_background_context():
    result = explain(parse("a"), assumptions=[parse("a <-> b")])

    assert isinstance(result, ExplainResult)
    assert _cubes(result.explanations) == {
        frozenset({("a", True)}),
        frozenset({("b", True)}),
    }


def test_explain_reports_truncation_and_resource_limits():
    truncated = explain(parse("a | b | c"), limit=2)
    limited = explain(parse("a | b"), max_explanation_cubes=1)

    assert isinstance(truncated, ExplainResult)
    assert len(truncated.explanations) == 2
    assert truncated.truncated is True
    assert isinstance(limited, ErrorResult)
    assert limited.error.code == "explanation_cube_limit"


def test_verify_and_diff_include_one_subset_minimal_explanation():
    verification = verify(parse("override"), parse("permission"))
    change = diff(parse("employee"), parse("employee | override"))

    assert not isinstance(verification, ErrorResult)
    assert verification.explanation == Explanation(
        (Literal("override", True), Literal("permission", False))
    )
    assert not isinstance(change, ErrorResult)
    assert change.added_access is not None
    assert change.added_access.explanation == Explanation(
        (Literal("employee", False), Literal("override", True))
    )


def test_document_explanations_and_report_include_atom_metadata():
    document = load_document(
        b'{"irVersion":"1","atoms":{"override":{"owner":"security"}},'
        b'"expressions":{"access":{"atom":"override"}},'
        b'"requirements":{"access":{"atom":"permission"}},'
        b'"metadata":{"title":"example"}}'
    )
    report = report_document(document)

    assert not isinstance(report, ErrorResult)
    assert report.entries[0].status == "violated"
    literals = report.entries[0].explanations[0].literals
    assert Literal("override", True, {"owner": "security"}) in literals
    assert Literal("permission", False) in literals


def test_report_lists_expressions_without_matching_requirements_as_unverified():
    document = load_document(
        b'{"irVersion":"1","expressions":{'
        b'"checked":{"atom":"a"},"unchecked":{"atom":"b"}},'
        b'"requirements":{"checked":{"atom":"a"}}}'
    )
    report = report_document(document)

    assert not isinstance(report, ErrorResult)
    assert report.entries[0].status == "holds"
    assert report.unverified_expressions == ("unchecked",)


def test_prime_implicants_match_brute_force_for_every_three_variable_function():
    variables = ("a", "b", "c")
    total_assignments = tuple(
        dict(zip(variables, values, strict=True))
        for values in product((False, True), repeat=len(variables))
    )

    for truth_table in range(1 << len(total_assignments)):
        expression = _expression_for_truth_table(truth_table, total_assignments)
        result = explain(expression, variable_order=variables, limit=27)

        assert isinstance(result, ExplainResult)
        assert result.truncated is False
        assert _cubes(result.explanations) == _brute_prime_implicants(
            expression, Constant(True), variables, total_assignments
        )


def test_explanations_match_brute_force_under_every_two_variable_constraint():
    variables = ("a", "b")
    total_assignments = tuple(
        dict(zip(variables, values, strict=True))
        for values in product((False, True), repeat=len(variables))
    )
    functions = tuple(
        _expression_for_truth_table(table, total_assignments) for table in range(16)
    )

    for constraint in functions[1:]:
        for expression in functions:
            result = explain(
                expression,
                assumptions=[constraint],
                variable_order=variables,
                limit=9,
            )

            assert isinstance(result, ExplainResult)
            assert result.truncated is False
            assert _cubes(result.explanations) == _brute_prime_implicants(
                expression, constraint, variables, total_assignments
            )


def _expression_for_truth_table(
    truth_table: int, assignments: tuple[dict[str, bool], ...]
):
    terms = []
    for index, assignment in enumerate(assignments):
        if not truth_table & (1 << index):
            continue
        terms.append(
            And(
                tuple(
                    Atom(name) if value else Not(Atom(name))
                    for name, value in assignment.items()
                )
            )
        )
    return Or(tuple(terms)) if terms else Constant(False)


def _brute_prime_implicants(expression, constraint, variables, total_assignments):
    prime = set()
    for values in product((None, False, True), repeat=len(variables)):
        cube = {
            name: value
            for name, value in zip(variables, values, strict=True)
            if value is not None
        }
        if not _sufficient(expression, constraint, cube, total_assignments):
            continue
        if all(
            not _sufficient(
                expression,
                constraint,
                {name: value for name, value in cube.items() if name != removed},
                total_assignments,
            )
            for removed in cube
        ):
            prime.add(frozenset(cube.items()))
    return prime


def _sufficient(expression, constraint, cube, total_assignments):
    extensions = [
        assignment
        for assignment in total_assignments
        if evaluate(constraint, assignment)
        if all(assignment[name] == value for name, value in cube.items())
    ]
    return bool(extensions) and all(evaluate(expression, item) for item in extensions)
