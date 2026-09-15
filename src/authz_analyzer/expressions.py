from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


def _require_expression(value: object) -> None:
    if not isinstance(value, _EXPRESSION_TYPES):
        raise TypeError("expression children must be expression nodes")


def _require_expression_tuple(values: object) -> None:
    if not isinstance(values, tuple):
        raise TypeError("n-ary expression arguments must be a tuple")
    for value in values:
        _require_expression(value)


@dataclass(frozen=True, slots=True)
class Constant:
    value: bool

    def __post_init__(self) -> None:
        if type(self.value) is not bool:
            raise TypeError("constant value must be a boolean")


@dataclass(frozen=True, slots=True)
class Atom:
    name: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str):
            raise TypeError("atom name must be a string")
        if not self.name:
            raise ValueError("atom name must not be empty")


@dataclass(frozen=True, slots=True)
class Not:
    arg: Expression

    def __post_init__(self) -> None:
        _require_expression(self.arg)


@dataclass(frozen=True, slots=True)
class And:
    args: tuple[Expression, ...]

    def __post_init__(self) -> None:
        _require_expression_tuple(self.args)


@dataclass(frozen=True, slots=True)
class Or:
    args: tuple[Expression, ...]

    def __post_init__(self) -> None:
        _require_expression_tuple(self.args)


@dataclass(frozen=True, slots=True)
class Xor:
    args: tuple[Expression, ...]

    def __post_init__(self) -> None:
        _require_expression_tuple(self.args)
        if len(self.args) < 2:
            raise ValueError("xor requires at least two arguments")


@dataclass(frozen=True, slots=True)
class Implies:
    left: Expression
    right: Expression

    def __post_init__(self) -> None:
        _require_expression(self.left)
        _require_expression(self.right)


@dataclass(frozen=True, slots=True)
class Equiv:
    left: Expression
    right: Expression

    def __post_init__(self) -> None:
        _require_expression(self.left)
        _require_expression(self.right)


type Expression = Constant | Atom | Not | And | Or | Xor | Implies | Equiv

_EXPRESSION_TYPES = (Constant, Atom, Not, And, Or, Xor, Implies, Equiv)


def all_of(*args: Expression) -> And:
    return And(args)


def any_of(*args: Expression) -> Or:
    return Or(args)


def evaluate(expression: Expression, assignment: Mapping[str, bool]) -> bool:
    """Evaluate an expression independently of the BDD implementation."""
    match expression:
        case Constant(value):
            return value
        case Atom(name):
            try:
                value = assignment[name]
            except KeyError:
                raise KeyError(f"missing assignment for atom: {name}") from None
            if type(value) is not bool:
                raise TypeError("assignment values must be boolean")
            return value
        case Not(arg):
            return not evaluate(arg, assignment)
        case And(args):
            return all(evaluate(arg, assignment) for arg in args)
        case Or(args):
            return any(evaluate(arg, assignment) for arg in args)
        case Xor(args):
            result = False
            for arg in args:
                result ^= evaluate(arg, assignment)
            return result
        case Implies(left, right):
            return not evaluate(left, assignment) or evaluate(right, assignment)
        case Equiv(left, right):
            return evaluate(left, assignment) == evaluate(right, assignment)
        case _:
            raise TypeError("expected an expression node")


def expression_node_count(expression: Expression) -> int:
    """Count expression nodes, including repeated subexpressions."""
    match expression:
        case Constant() | Atom():
            return 1
        case Not(arg):
            return 1 + expression_node_count(arg)
        case And(args) | Or(args) | Xor(args):
            return 1 + sum(expression_node_count(arg) for arg in args)
        case Implies(left, right) | Equiv(left, right):
            return 1 + expression_node_count(left) + expression_node_count(right)
        case _:
            raise TypeError("expected an expression node")


__all__ = [
    "And",
    "Atom",
    "Constant",
    "Equiv",
    "Expression",
    "Implies",
    "Not",
    "Or",
    "Xor",
    "all_of",
    "any_of",
    "evaluate",
    "expression_node_count",
]
