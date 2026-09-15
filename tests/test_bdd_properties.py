from bdd_oracle import assignments, atoms, compile_expression, evaluate
from hypothesis import given, settings
from hypothesis import strategies as st

from authz_analyzer import BDDOperation, BinaryDecisionDiagram

ATOM = st.sampled_from(["a", "b", "c", "d"])
LEAF = st.one_of(st.booleans(), ATOM)
EXPRESSIONS = st.recursive(
    LEAF,
    lambda children: st.one_of(
        st.tuples(st.just("not"), children),
        st.tuples(
            st.sampled_from(["and", "or", "xor", "implies", "equiv"]),
            children,
            children,
        ),
        st.tuples(st.just("ite"), children, children, children),
    ),
    max_leaves=8,
)


@given(EXPRESSIONS)
@settings(max_examples=200, deadline=None)
def test_bdd_matches_independent_truth_table(expression):
    variables = sorted(atoms(expression))
    bdd, root = compile_expression(expression, variables)
    for assignment in assignments(variables):
        assert bdd.evaluate(root, assignment) == evaluate(expression, assignment)


@given(EXPRESSIONS, st.dictionaries(ATOM, st.booleans(), max_size=4))
@settings(max_examples=150, deadline=None)
def test_restriction_matches_independent_truth_table(expression, fixed):
    variables = sorted(atoms(expression))
    fixed = {name: value for name, value in fixed.items() if name in variables}
    bdd, root = compile_expression(expression, variables)
    restricted = bdd.restrict(root, fixed)
    remaining = [name for name in variables if name not in fixed]
    for rest in assignments(remaining):
        complete = fixed | rest
        assert bdd.evaluate(restricted, complete) == evaluate(expression, complete)


@given(EXPRESSIONS)
@settings(max_examples=200, deadline=None)
def test_pick_sat_returns_a_sufficient_partial_assignment(expression):
    variables = sorted(atoms(expression))
    bdd, root = compile_expression(expression, variables)
    witness = bdd.pick_sat(root)
    satisfying = [
        assignment
        for assignment in assignments(variables)
        if evaluate(expression, assignment)
    ]
    assert (witness is None) == (not satisfying)
    if witness is not None:
        extensions = [
            assignment
            for assignment in assignments(variables)
            if assignment.items() >= witness.items()
        ]
        assert extensions
        assert all(evaluate(expression, assignment) for assignment in extensions)


@given(EXPRESSIONS, ATOM)
@settings(max_examples=150, deadline=None)
def test_quantification_matches_restriction_definition(expression, variable):
    variables = sorted(atoms(expression) | {variable})
    bdd, root = compile_expression(expression, variables)
    low = bdd.restrict(root, {variable: False})
    high = bdd.restrict(root, {variable: True})
    expected_exists = bdd.apply(BDDOperation.OR, low, high)
    expected_forall = bdd.apply(BDDOperation.AND, low, high)
    assert bdd.exists(root, {variable}) == expected_exists
    assert bdd.forall(root, {variable}) == expected_forall

    remaining = [name for name in variables if name != variable]
    exists_root = bdd.exists(root, {variable})
    forall_root = bdd.forall(root, {variable})
    for assignment in assignments(remaining):
        when_false = evaluate(expression, assignment | {variable: False})
        when_true = evaluate(expression, assignment | {variable: True})
        assert bdd.evaluate(exists_root, assignment) == (when_false or when_true)
        assert bdd.evaluate(forall_root, assignment) == (when_false and when_true)


@given(EXPRESSIONS, EXPRESSIONS, EXPRESSIONS)
@settings(max_examples=150, deadline=None)
def test_boolean_identities(first, second, third):
    variables = sorted(atoms(first) | atoms(second) | atoms(third))
    bdd = BinaryDecisionDiagram(variables)

    def build(expression):
        if isinstance(expression, bool):
            return bdd.TRUE if expression else bdd.FALSE
        if isinstance(expression, str):
            return bdd.var(expression)
        operation, *children = expression
        return bdd.apply(BDDOperation(operation), *(build(c) for c in children))

    f, g, h = build(first), build(second), build(third)
    assert bdd.apply(BDDOperation.NOT, bdd.apply(BDDOperation.NOT, f)) == f
    assert bdd.apply(BDDOperation.AND, f, f) == f
    assert bdd.apply(BDDOperation.OR, f, f) == f
    assert bdd.apply(BDDOperation.AND, f, -f) == bdd.FALSE
    assert bdd.apply(BDDOperation.OR, f, -f) == bdd.TRUE
    assert bdd.apply(BDDOperation.AND, f, g) == bdd.apply(BDDOperation.AND, g, f)
    assert bdd.apply(BDDOperation.OR, f, g) == bdd.apply(BDDOperation.OR, g, f)
    left = bdd.apply(BDDOperation.AND, f, bdd.apply(BDDOperation.OR, g, h))
    right = bdd.apply(
        BDDOperation.OR,
        bdd.apply(BDDOperation.AND, f, g),
        bdd.apply(BDDOperation.AND, f, h),
    )
    assert left == right
    assert bdd.apply(BDDOperation.ITE, f, g, h) == bdd.apply(
        BDDOperation.OR,
        bdd.apply(BDDOperation.AND, f, g),
        bdd.apply(BDDOperation.AND, -f, h),
    )
