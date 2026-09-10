from collections.abc import Iterable

from authz_analyzer.bdd import BDDOperation, BinaryDecisionDiagram, NodeRef
from authz_analyzer.expressions import (
    And,
    Atom,
    Constant,
    Equiv,
    Expression,
    Implies,
    Not,
    Or,
    Xor,
)


def _children(expression: Expression) -> tuple[Expression, ...]:
    match expression:
        case Constant() | Atom():
            return ()
        case Not(arg):
            return (arg,)
        case And(args) | Or(args) | Xor(args):
            return args
        case Implies(left, right) | Equiv(left, right):
            return left, right
        case _:
            raise TypeError("expected an expression node")


def _atom_order(expression: Expression) -> tuple[str, ...]:
    names: dict[str, None] = {}

    def visit(node: Expression) -> None:
        if isinstance(node, Atom):
            names.setdefault(node.name, None)
        for child in _children(node):
            visit(child)

    visit(expression)
    return tuple(names)


def compile_expression(
    expression: Expression,
    *,
    variable_order: Iterable[str] | None = None,
) -> tuple[BinaryDecisionDiagram, NodeRef]:
    """Compile an expression into a new BDD manager and its root reference."""
    atom_order = _atom_order(expression)
    variables = atom_order if variable_order is None else tuple(variable_order)
    missing = [name for name in atom_order if name not in variables]
    if missing:
        raise ValueError(f"variable order is missing atoms: {', '.join(missing)}")

    bdd = BinaryDecisionDiagram(variables)
    memo: dict[Expression, NodeRef] = {}

    def compile_node(node: Expression) -> NodeRef:
        if node in memo:
            return memo[node]

        match node:
            case Constant(value):
                result = bdd.TRUE if value else bdd.FALSE
            case Atom(name):
                result = bdd.var(name)
            case Not(arg):
                result = bdd.apply(BDDOperation.NOT, compile_node(arg))
            case And(args):
                result = bdd.TRUE
                for arg in args:
                    result = bdd.apply(BDDOperation.AND, result, compile_node(arg))
            case Or(args):
                result = bdd.FALSE
                for arg in args:
                    result = bdd.apply(BDDOperation.OR, result, compile_node(arg))
            case Xor(args):
                result = bdd.FALSE
                for arg in args:
                    result = bdd.apply(BDDOperation.XOR, result, compile_node(arg))
            case Implies(left, right):
                result = bdd.apply(
                    BDDOperation.IMPLIES, compile_node(left), compile_node(right)
                )
            case Equiv(left, right):
                result = bdd.apply(
                    BDDOperation.EQUIV, compile_node(left), compile_node(right)
                )
            case _:
                raise TypeError("expected an expression node")

        memo[node] = result
        return result

    return bdd, compile_node(expression)


__all__ = ["compile_expression"]
