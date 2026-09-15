import pytest
from bdd_oracle import assignments
from cudd_oracle import cudd_value
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import Bundle, RuleBasedStateMachine, initialize, rule

from authz_analyzer import BDDOperation, BinaryDecisionDiagram

CuddBDD = pytest.importorskip("dd.cudd").BDD

VARIABLES = ("a", "b", "c")
BINARY_OPERATIONS = st.sampled_from(
    [
        BDDOperation.AND,
        BDDOperation.OR,
        BDDOperation.XOR,
        BDDOperation.IMPLIES,
        BDDOperation.EQUIV,
    ]
)


class BDDDifferentialMachine(RuleBasedStateMachine):
    nodes = Bundle("nodes")

    @initialize()
    def create_managers(self):
        self.ours = BinaryDecisionDiagram(list(VARIABLES))
        self.cudd = CuddBDD()
        self.cudd.declare(*VARIABLES)

    def assert_equivalent(self, ours, cudd):
        for assignment in assignments(list(VARIABLES)):
            assert self.ours.evaluate(ours, assignment) == cudd_value(
                self.cudd, cudd, assignment
            )

    @rule(target=nodes, value=st.booleans())
    def constant(self, value):
        return (
            self.ours.TRUE if value else self.ours.FALSE,
            self.cudd.true if value else self.cudd.false,
        )

    @rule(target=nodes, variable=st.sampled_from(VARIABLES))
    def variable(self, variable):
        return self.ours.var(variable), self.cudd.var(variable)

    @rule(target=nodes, node=nodes)
    def negate(self, node):
        ours, cudd = node
        result = -ours, ~cudd
        self.assert_equivalent(*result)
        return result

    @rule(target=nodes, operation=BINARY_OPERATIONS, left=nodes, right=nodes)
    def binary(self, operation, left, right):
        ours_left, cudd_left = left
        ours_right, cudd_right = right
        ours = self.ours.apply(operation, ours_left, ours_right)
        if operation is BDDOperation.AND:
            cudd = cudd_left & cudd_right
        elif operation is BDDOperation.OR:
            cudd = cudd_left | cudd_right
        elif operation is BDDOperation.XOR:
            cudd = self.cudd.apply("xor", cudd_left, cudd_right)
        elif operation is BDDOperation.IMPLIES:
            cudd = ~cudd_left | cudd_right
        else:
            cudd = self.cudd.apply("equiv", cudd_left, cudd_right)
        self.assert_equivalent(ours, cudd)
        return ours, cudd

    @rule(
        target=nodes,
        node=nodes,
        fixed=st.dictionaries(st.sampled_from(VARIABLES), st.booleans()),
    )
    def restrict(self, node, fixed):
        ours, cudd = node
        result = self.ours.restrict(ours, fixed), self.cudd.let(fixed, cudd)
        self.assert_equivalent(*result)
        return result

    @rule(
        target=nodes,
        node=nodes,
        quantified=st.sets(st.sampled_from(VARIABLES)),
        for_all=st.booleans(),
    )
    def quantify(self, node, quantified, for_all):
        ours, cudd = node
        if for_all:
            result = (
                self.ours.forall(ours, quantified),
                self.cudd.forall(quantified, cudd),
            )
        else:
            result = (
                self.ours.exists(ours, quantified),
                self.cudd.exist(quantified, cudd),
            )
        self.assert_equivalent(*result)
        return result


TestBDDDifferential = BDDDifferentialMachine.TestCase
TestBDDDifferential.settings = settings(
    max_examples=50,
    stateful_step_count=30,
    deadline=None,
)
