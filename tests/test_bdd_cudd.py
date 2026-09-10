from dd.cudd import BDD as CuddBDD
from hypothesis import given, settings, strategies as st

from authz_analyzer import BDDOperation, BinaryDecisionDiagram

from bdd_oracle import assignments, atoms, compile_expression
from cudd_oracle import cudd_value

ATOM = st.sampled_from(["a", "b", "c", "d", "e"])
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
    max_leaves=10,
)


def compile_cudd(expression, variables):
    bdd = CuddBDD()
    bdd.declare(*variables)

    def build(node):
        if isinstance(node, bool):
            return bdd.true if node else bdd.false
        if isinstance(node, str):
            return bdd.var(node)
        operation, *children = node
        refs = [build(child) for child in children]
        if operation == "not":
            return ~refs[0]
        if operation == "and":
            return refs[0] & refs[1]
        if operation == "or":
            return refs[0] | refs[1]
        if operation == "xor":
            return bdd.apply("xor", refs[0], refs[1])
        if operation == "implies":
            return ~refs[0] | refs[1]
        if operation == "equiv":
            return bdd.apply("equiv", refs[0], refs[1])
        if operation == "ite":
            return bdd.ite(*refs)
        raise AssertionError(f"Unknown operation: {operation}")

    return bdd, build(expression)


@given(EXPRESSIONS)
@settings(max_examples=250, deadline=None)
def test_generated_expressions_match_cudd(expression):
    variables = sorted(atoms(expression))
    ours, our_root = compile_expression(expression, variables)
    cudd, cudd_root = compile_cudd(expression, variables)

    assert set(ours.support(our_root)) == cudd.support(cudd_root)
    assert ours.is_satisfiable(our_root) == (cudd_root != cudd.false)
    for assignment in assignments(variables):
        assert ours.evaluate(our_root, assignment) == cudd_value(
            cudd, cudd_root, assignment
        )


@given(EXPRESSIONS, st.dictionaries(ATOM, st.booleans(), max_size=5))
@settings(max_examples=200, deadline=None)
def test_generated_restrictions_match_cudd(expression, fixed):
    variables = sorted(atoms(expression))
    fixed = {name: value for name, value in fixed.items() if name in variables}
    ours, our_root = compile_expression(expression, variables)
    cudd, cudd_root = compile_cudd(expression, variables)
    our_restricted = ours.restrict(our_root, fixed)
    cudd_restricted = cudd.let(fixed, cudd_root) if fixed else cudd_root

    remaining = [name for name in variables if name not in fixed]
    for assignment in assignments(remaining):
        assert ours.evaluate(our_restricted, assignment) == cudd_value(
            cudd, cudd_restricted, assignment
        )


@given(EXPRESSIONS, st.sets(ATOM, max_size=5))
@settings(max_examples=200, deadline=None)
def test_generated_quantification_matches_cudd(expression, requested_variables):
    variables = sorted(atoms(expression) | requested_variables)
    quantified = sorted(requested_variables)
    ours, our_root = compile_expression(expression, variables)
    cudd, cudd_root = compile_cudd(expression, variables)

    our_exists = ours.exists(our_root, set(quantified))
    our_forall = ours.forall(our_root, set(quantified))
    cudd_exists = cudd.exist(quantified, cudd_root)
    cudd_forall = cudd.forall(quantified, cudd_root)
    remaining = [name for name in variables if name not in requested_variables]
    for assignment in assignments(remaining):
        assert ours.evaluate(our_exists, assignment) == cudd_value(
            cudd, cudd_exists, assignment
        )
        assert ours.evaluate(our_forall, assignment) == cudd_value(
            cudd, cudd_forall, assignment
        )
