import json
from itertools import product
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from authz_analyzer.compile import compile_expressions
from authz_analyzer.expressions import (
    And,
    Atom,
    Constant,
    Equiv,
    Implies,
    Not,
    Or,
    Xor,
    evaluate,
)
from authz_analyzer.json_codec import (
    IRCodecError,
    document_from_data,
    document_to_data,
    dump_document,
    dump_expression,
    expression_from_data,
    expression_to_data,
    load_document,
    load_expression,
)
from authz_analyzer.parser import parse

SCHEMA_PATH = Path(__file__).parents[1] / "schemas" / "boolean-ir-v1.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


CASES = [
    (Constant(True), {"const": True}),
    (Atom("NAME"), {"atom": "NAME"}),
    (Not(Atom("a")), {"op": "not", "arg": {"atom": "a"}}),
    (And(()), {"op": "and", "args": []}),
    (
        Or((Atom("a"), Constant(False))),
        {"op": "or", "args": [{"atom": "a"}, {"const": False}]},
    ),
    (
        Xor((Atom("a"), Atom("b"))),
        {"op": "xor", "args": [{"atom": "a"}, {"atom": "b"}]},
    ),
    (
        Implies(Atom("a"), Atom("b")),
        {"op": "implies", "left": {"atom": "a"}, "right": {"atom": "b"}},
    ),
    (
        Equiv(Atom("a"), Atom("b")),
        {"op": "equiv", "left": {"atom": "a"}, "right": {"atom": "b"}},
    ),
]


@pytest.mark.parametrize(("expression", "data"), CASES)
def test_expression_data_round_trip(expression, data) -> None:
    assert expression_to_data(expression) == data
    assert expression_from_data(data) == expression


def _expressions():
    leaves = st.sampled_from(
        [Constant(False), Constant(True), Atom("a"), Atom("has space")]
    )
    return st.recursive(
        leaves,
        lambda children: st.one_of(
            children.map(Not),
            st.lists(children, max_size=3).map(lambda args: And(tuple(args))),
            st.lists(children, max_size=3).map(lambda args: Or(tuple(args))),
            st.lists(children, min_size=2, max_size=3).map(
                lambda args: Xor(tuple(args))
            ),
            st.tuples(children, children).map(lambda args: Implies(*args)),
            st.tuples(children, children).map(lambda args: Equiv(*args)),
        ),
        max_leaves=12,
    )


@given(_expressions())
def test_json_round_trip_is_lossless(expression) -> None:
    assert load_expression(dump_expression(expression)) == expression


@given(_expressions())
def test_every_encoded_expression_matches_the_published_schema(expression) -> None:
    VALIDATOR.validate(
        {
            "irVersion": "1",
            "expressions": {"test": expression_to_data(expression)},
        }
    )


def test_dump_is_compact_deterministic_unicode_json() -> None:
    expression = Not(Atom("λ permission"))

    assert dump_expression(expression) == '{"arg":{"atom":"λ permission"},"op":"not"}'


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        {},
        {"const": 1},
        {"atom": 1},
        {"atom": ""},
        {"atom": "a", "extra": True},
        {"op": "unknown", "args": []},
        {"op": "not"},
        {"op": "not", "arg": {"atom": "a"}, "extra": 1},
        {"op": "and", "args": {}},
        {"op": "xor", "args": [{"atom": "a"}]},
        {"op": "implies", "left": {"atom": "a"}},
        {"op": "equiv", "left": {"atom": "a"}, "right": False},
    ],
)
def test_decoder_rejects_malformed_semantic_nodes(data) -> None:
    with pytest.raises(IRCodecError):
        expression_from_data(data)


@pytest.mark.parametrize(
    "source",
    [
        '{"atom":"a","atom":"b"}',
        '{"op":"not","arg":{"atom":"a","atom":"b"}}',
    ],
)
def test_loader_rejects_duplicate_object_keys(source: str) -> None:
    with pytest.raises(IRCodecError, match="duplicate.*atom"):
        load_expression(source)


def test_loader_wraps_invalid_json() -> None:
    with pytest.raises(IRCodecError) as error:
        load_expression('{"atom":')

    assert error.value.code == "invalid_json"
    assert (error.value.line, error.value.column) == (1, 9)


def test_loader_rejects_nonstandard_json_numbers() -> None:
    source = (
        '{"irVersion":"1","expressions":{"x":{"const":true}},'
        '"metadata":{"extensions":{"value":NaN}}}'
    )

    with pytest.raises(IRCodecError) as error:
        load_document(source)

    assert error.value.code == "invalid_json"


def test_schema_is_valid_and_matches_codec_cases() -> None:
    Draft202012Validator.check_schema(SCHEMA)

    for _, data in CASES:
        VALIDATOR.validate({"irVersion": "1", "expressions": {"test": data}})
    with pytest.raises(ValidationError):
        VALIDATOR.validate(
            {
                "irVersion": "1",
                "expressions": {"test": {"op": "xor", "args": [{"atom": "a"}]}},
            }
        )
    with pytest.raises(ValidationError):
        VALIDATOR.validate(
            {
                "irVersion": "1",
                "expressions": {"test": {"atom": "a", "extra": True}},
            }
        )


def test_document_round_trip_preserves_expressions_and_metadata() -> None:
    source = (Path(__file__).parents[1] / "examples" / "pii-access.json").read_text()
    document = load_document(source)

    assert document.ir_version == "1"
    assert set(document.expressions) == {"user.ssn"}
    assert document.atoms["PII_READ"].owner == "privacy-platform"
    assert document.atoms["PII_READ"].provenance[0].line == 42
    assert load_document(dump_document(document)) == document
    assert document_from_data(document_to_data(document)) == document


def test_document_extensions_are_preserved_losslessly() -> None:
    data = {
        "irVersion": "1",
        "expressions": {"access": {"atom": "a"}},
        "atoms": {"a": {"extensions": {"com.example.data": {"nested": [1, True]}}}},
        "metadata": {"extensions": {"com.example.revision": "abc123"}},
    }

    assert document_to_data(document_from_data(data)) == data


@pytest.mark.parametrize(
    ("data", "code", "pointer"),
    [
        ({}, "invalid_document", ""),
        (
            {"irVersion": "2", "expressions": {"x": {"const": True}}},
            "unsupported_version",
            "/irVersion",
        ),
        ({"irVersion": "1", "expressions": {}}, "invalid_document", "/expressions"),
        (
            {"irVersion": "1", "expressions": {"": {"const": True}}},
            "invalid_document",
            "/expressions",
        ),
        (
            {"irVersion": "1", "expressions": {"x": {"atom": ""}}},
            "invalid_expression",
            "/expressions/x/atom",
        ),
        (
            {
                "irVersion": "1",
                "expressions": {"x": {"const": True}},
                "atoms": {"a": {"provenance": [{"source": "x", "line": 0}]}},
            },
            "invalid_document",
            "/atoms/a/provenance/0/line",
        ),
        (
            {"irVersion": "1", "expressions": {"x": {"const": True}}, "unknown": True},
            "invalid_document",
            "",
        ),
        (
            {
                "irVersion": "1",
                "expressions": {"x": {"const": True}},
                "metadata": {"extensions": {"value": float("nan")}},
            },
            "invalid_document",
            "/metadata/extensions/value",
        ),
    ],
)
def test_document_decoder_rejects_invalid_documents(data, code, pointer) -> None:
    with pytest.raises(IRCodecError) as error:
        document_from_data(data)

    assert error.value.code == code
    assert error.value.pointer == pointer


def test_document_loader_rejects_duplicate_nested_keys() -> None:
    source = '{"irVersion":"1","expressions":{"x":{"atom":"a","atom":"b"}}}'

    with pytest.raises(IRCodecError) as error:
        load_document(source)

    assert error.value.code == "duplicate_key"


def test_string_ast_and_json_compile_to_the_same_function() -> None:
    parsed = parse('admin | (owner & !"account suspended")')
    decoded = load_expression(dump_expression(parsed))
    bdd, roots = compile_expressions((parsed, decoded))

    assert roots[0] == roots[1]
    for values in product((False, True), repeat=len(bdd.variables)):
        assignment = dict(zip(bdd.variables, values, strict=True))
        assert bdd.evaluate(roots[0], assignment) is evaluate(parsed, assignment)
