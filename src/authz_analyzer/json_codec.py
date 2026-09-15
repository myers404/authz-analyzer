import json
import math
from typing import Never

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
from authz_analyzer.ir import (
    AtomMetadata,
    DocumentMetadata,
    IRDocument,
    JSONValue,
    Provenance,
)


class IRCodecError(ValueError):
    def __init__(
        self,
        code: str,
        message: str,
        pointer: str = "",
        *,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.pointer = pointer
        self.line = line
        self.column = column
        location = pointer or "/"
        super().__init__(f"{code} at {location}: {message}")


def expression_to_data(expression: Expression) -> dict[str, object]:
    match expression:
        case Constant(value):
            return {"const": value}
        case Atom(name):
            return {"atom": name}
        case Not(arg):
            return {"op": "not", "arg": expression_to_data(arg)}
        case And(args):
            return {"op": "and", "args": _args_to_data(args)}
        case Or(args):
            return {"op": "or", "args": _args_to_data(args)}
        case Xor(args):
            return {"op": "xor", "args": _args_to_data(args)}
        case Implies(left, right):
            return {
                "op": "implies",
                "left": expression_to_data(left),
                "right": expression_to_data(right),
            }
        case Equiv(left, right):
            return {
                "op": "equiv",
                "left": expression_to_data(left),
                "right": expression_to_data(right),
            }
        case _:
            raise TypeError("expected an expression node")


def _args_to_data(args: tuple[Expression, ...]) -> list[dict[str, object]]:
    return [expression_to_data(arg) for arg in args]


def expression_from_data(data: object) -> Expression:
    return _expression_from_data(data, "")


def _expression_from_data(data: object, pointer: str) -> Expression:
    if not isinstance(data, dict):
        _fail("invalid_expression", "expression must be an object", pointer)

    if "const" in data:
        _require_shape(data, {"const"}, set(), pointer, "invalid_expression")
        value = data["const"]
        if type(value) is not bool:
            _fail("invalid_expression", "must be a boolean", _at(pointer, "const"))
        return Constant(value)

    if "atom" in data:
        _require_shape(data, {"atom"}, set(), pointer, "invalid_expression")
        name = data["atom"]
        if not isinstance(name, str):
            _fail("invalid_expression", "must be a string", _at(pointer, "atom"))
        if not name:
            _fail("invalid_expression", "must not be empty", _at(pointer, "atom"))
        return Atom(name)

    operation = data.get("op")
    if not isinstance(operation, str):
        _fail(
            "invalid_expression",
            "expected 'const', 'atom', or string 'op'",
            pointer,
        )

    if operation == "not":
        _require_shape(data, {"op", "arg"}, set(), pointer, "invalid_expression")
        return Not(_expression_from_data(data["arg"], _at(pointer, "arg")))

    if operation in {"and", "or", "xor"}:
        _require_shape(data, {"op", "args"}, set(), pointer, "invalid_expression")
        raw_args = data["args"]
        args_pointer = _at(pointer, "args")
        if not isinstance(raw_args, list):
            _fail("invalid_expression", "must be an array", args_pointer)
        if operation == "xor" and len(raw_args) < 2:
            _fail(
                "invalid_expression",
                "xor requires at least two arguments",
                args_pointer,
            )
        args = tuple(
            _expression_from_data(arg, _at(args_pointer, index))
            for index, arg in enumerate(raw_args)
        )
        if operation == "and":
            return And(args)
        if operation == "or":
            return Or(args)
        return Xor(args)

    if operation in {"implies", "equiv"}:
        _require_shape(
            data,
            {"op", "left", "right"},
            set(),
            pointer,
            "invalid_expression",
        )
        left = _expression_from_data(data["left"], _at(pointer, "left"))
        right = _expression_from_data(data["right"], _at(pointer, "right"))
        return Implies(left, right) if operation == "implies" else Equiv(left, right)

    _fail(
        "invalid_expression",
        f"unknown operator {operation!r}",
        _at(pointer, "op"),
    )


def document_from_data(data: object) -> IRDocument:
    if not isinstance(data, dict):
        _fail("invalid_document", "document must be an object", "")
    _require_shape(
        data,
        {"irVersion", "expressions"},
        {"atoms", "requirements", "assumptions", "metadata"},
        "",
        "invalid_document",
    )

    version = data["irVersion"]
    if version != "1":
        _fail(
            "unsupported_version",
            "irVersion must equal '1'",
            "/irVersion",
        )

    expressions = _expression_map(data["expressions"], "/expressions", required=True)
    atoms = _atom_catalog(data["atoms"], "/atoms") if "atoms" in data else None
    requirements = (
        _expression_map(data["requirements"], "/requirements")
        if "requirements" in data
        else None
    )
    assumptions = (
        _assumptions(data["assumptions"], "/assumptions")
        if "assumptions" in data
        else None
    )
    metadata = (
        _document_metadata(data["metadata"], "/metadata")
        if "metadata" in data
        else None
    )
    return IRDocument(
        ir_version="1",
        expressions=expressions,
        atoms=atoms,
        requirements=requirements,
        assumptions=assumptions,
        metadata=metadata,
    )


def _expression_map(
    value: object, pointer: str, *, required: bool = False
) -> dict[str, Expression]:
    if not isinstance(value, dict):
        _fail("invalid_document", "must be an object", pointer)
    if required and not value:
        _fail("invalid_document", "must contain at least one expression", pointer)
    result: dict[str, Expression] = {}
    for name, expression in value.items():
        if not isinstance(name, str) or not name:
            _fail("invalid_document", "names must not be empty", pointer)
        result[name] = _expression_from_data(expression, _at(pointer, name))
    return result


def _assumptions(value: object, pointer: str) -> tuple[Expression, ...]:
    if not isinstance(value, list):
        _fail("invalid_document", "must be an array", pointer)
    return tuple(
        _expression_from_data(expression, _at(pointer, index))
        for index, expression in enumerate(value)
    )


def _atom_catalog(value: object, pointer: str) -> dict[str, AtomMetadata]:
    if not isinstance(value, dict):
        _fail("invalid_document", "must be an object", pointer)
    result = {}
    for name, metadata in value.items():
        if not isinstance(name, str) or not name:
            _fail("invalid_document", "atom names must not be empty", pointer)
        result[name] = _atom_metadata(metadata, _at(pointer, name))
    return result


def _atom_metadata(value: object, pointer: str) -> AtomMetadata:
    if not isinstance(value, dict):
        _fail("invalid_document", "atom metadata must be an object", pointer)
    _require_shape(
        value,
        set(),
        {"description", "category", "owner", "tags", "provenance", "extensions"},
        pointer,
        "invalid_document",
    )
    description = _optional_string(value, "description", pointer)
    category = _optional_string(value, "category", pointer)
    owner = _optional_string(value, "owner", pointer)

    tags = None
    if "tags" in value:
        raw_tags = value["tags"]
        if not isinstance(raw_tags, list) or not all(
            isinstance(tag, str) for tag in raw_tags
        ):
            _fail(
                "invalid_document",
                "must be an array of strings",
                _at(pointer, "tags"),
            )
        tags = tuple(raw_tags)

    provenance = None
    if "provenance" in value:
        raw_provenance = value["provenance"]
        if not isinstance(raw_provenance, list):
            _fail("invalid_document", "must be an array", _at(pointer, "provenance"))
        provenance = tuple(
            _provenance(item, _at(_at(pointer, "provenance"), index))
            for index, item in enumerate(raw_provenance)
        )

    extensions = _extensions(value, pointer)
    return AtomMetadata(
        description=description,
        category=category,
        owner=owner,
        tags=tags,
        provenance=provenance,
        extensions=extensions,
    )


def _provenance(value: object, pointer: str) -> Provenance:
    if not isinstance(value, dict):
        _fail("invalid_document", "provenance must be an object", pointer)
    fields = {"source", "line", "column", "pointer", "symbol", "note"}
    _require_shape(value, set(), fields, pointer, "invalid_document")
    if not any(field in value for field in ("source", "pointer", "symbol", "note")):
        _fail("invalid_document", "provenance must identify a location", pointer)

    source = _optional_string(value, "source", pointer)
    if source == "":
        _fail("invalid_document", "must not be empty", _at(pointer, "source"))
    line = _positive_integer(value, "line", pointer)
    column = _positive_integer(value, "column", pointer)
    return Provenance(
        source=source,
        line=line,
        column=column,
        pointer=_optional_string(value, "pointer", pointer),
        symbol=_optional_string(value, "symbol", pointer),
        note=_optional_string(value, "note", pointer),
    )


def _document_metadata(value: object, pointer: str) -> DocumentMetadata:
    if not isinstance(value, dict):
        _fail("invalid_document", "metadata must be an object", pointer)
    _require_shape(
        value,
        set(),
        {"title", "description", "extensions"},
        pointer,
        "invalid_document",
    )
    return DocumentMetadata(
        title=_optional_string(value, "title", pointer),
        description=_optional_string(value, "description", pointer),
        extensions=_extensions(value, pointer),
    )


def _optional_string(
    data: dict[object, object], field: str, pointer: str
) -> str | None:
    if field not in data:
        return None
    value = data[field]
    if not isinstance(value, str):
        _fail("invalid_document", "must be a string", _at(pointer, field))
    return value


def _positive_integer(
    data: dict[object, object], field: str, pointer: str
) -> int | None:
    if field not in data:
        return None
    value = data[field]
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        _fail("invalid_document", "must be a positive integer", _at(pointer, field))
    return value


def _extensions(
    data: dict[object, object], pointer: str
) -> dict[str, JSONValue] | None:
    if "extensions" not in data:
        return None
    value = data["extensions"]
    if not isinstance(value, dict):
        _fail("invalid_document", "must be an object", _at(pointer, "extensions"))
    return _json_object(value, _at(pointer, "extensions"))


def _json_object(value: dict[object, object], pointer: str) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            _fail("invalid_document", "JSON object keys must be strings", pointer)
        result[key] = _json_value(item, _at(pointer, key))
    return result


def _json_value(value: object, pointer: str) -> JSONValue:
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    if isinstance(value, list):
        return [
            _json_value(item, _at(pointer, index)) for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        return _json_object(value, pointer)
    _fail("invalid_document", "must be a JSON value", pointer)


def document_to_data(document: IRDocument) -> dict[str, object]:
    if not isinstance(document, IRDocument):
        raise TypeError("expected an IRDocument")
    data: dict[str, object] = {
        "irVersion": document.ir_version,
        "expressions": {
            name: expression_to_data(expression)
            for name, expression in document.expressions.items()
        },
    }
    if document.atoms is not None:
        data["atoms"] = {
            name: atom_metadata_to_data(metadata)
            for name, metadata in document.atoms.items()
        }
    if document.requirements is not None:
        data["requirements"] = {
            name: expression_to_data(expression)
            for name, expression in document.requirements.items()
        }
    if document.assumptions is not None:
        data["assumptions"] = [
            expression_to_data(expression) for expression in document.assumptions
        ]
    if document.metadata is not None:
        data["metadata"] = _document_metadata_to_data(document.metadata)
    document_from_data(data)
    return data


def atom_metadata_to_data(metadata: AtomMetadata) -> dict[str, object]:
    result: dict[str, object] = {}
    _add_if_present(result, "description", metadata.description)
    _add_if_present(result, "category", metadata.category)
    _add_if_present(result, "owner", metadata.owner)
    if metadata.tags is not None:
        result["tags"] = list(metadata.tags)
    if metadata.provenance is not None:
        result["provenance"] = [
            _provenance_to_data(item) for item in metadata.provenance
        ]
    if metadata.extensions is not None:
        result["extensions"] = metadata.extensions
    return result


def _provenance_to_data(provenance: Provenance) -> dict[str, object]:
    result: dict[str, object] = {}
    for field in ("source", "line", "column", "pointer", "symbol", "note"):
        _add_if_present(result, field, getattr(provenance, field))
    return result


def _document_metadata_to_data(metadata: DocumentMetadata) -> dict[str, object]:
    result: dict[str, object] = {}
    _add_if_present(result, "title", metadata.title)
    _add_if_present(result, "description", metadata.description)
    if metadata.extensions is not None:
        result["extensions"] = metadata.extensions
    return result


def _add_if_present(result: dict[str, object], key: str, value: object) -> None:
    if value is not None:
        result[key] = value


def _require_shape(
    data: dict[object, object],
    required: set[str],
    optional: set[str],
    pointer: str,
    code: str,
) -> None:
    actual = set(data)
    missing = required - actual
    unknown = actual - required - optional
    if not missing and not unknown:
        return
    details = []
    if missing:
        details.append(f"missing {', '.join(sorted(missing))}")
    if unknown:
        details.append(f"unknown {', '.join(sorted(repr(key) for key in unknown))}")
    _fail(code, "; ".join(details), pointer)


def _at(pointer: str, token: str | int) -> str:
    escaped = str(token).replace("~", "~0").replace("/", "~1")
    return f"{pointer}/{escaped}"


def _fail(code: str, message: str, pointer: str) -> Never:
    raise IRCodecError(code, message, pointer)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IRCodecError("duplicate_key", f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_number(value: str) -> Never:
    raise IRCodecError("invalid_json", f"nonstandard number: {value}")


def _load_json(source: str | bytes | bytearray) -> object:
    try:
        return json.loads(
            source,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonstandard_number,
        )
    except IRCodecError:
        raise
    except json.JSONDecodeError as error:
        raise IRCodecError(
            "invalid_json",
            error.msg,
            line=error.lineno,
            column=error.colno,
        ) from None
    except TypeError as error:
        raise IRCodecError("invalid_json", str(error)) from None


def _dump_json(data: object) -> str:
    try:
        return json.dumps(
            data,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise IRCodecError("invalid_document", str(error)) from None


def dump_expression(expression: Expression) -> str:
    return _dump_json(expression_to_data(expression))


def load_expression(source: str | bytes | bytearray) -> Expression:
    return expression_from_data(_load_json(source))


def dump_document(document: IRDocument) -> str:
    return _dump_json(document_to_data(document))


def load_document(source: str | bytes | bytearray) -> IRDocument:
    return document_from_data(_load_json(source))


__all__ = [
    "IRCodecError",
    "atom_metadata_to_data",
    "document_from_data",
    "document_to_data",
    "dump_document",
    "dump_expression",
    "expression_from_data",
    "expression_to_data",
    "load_document",
    "load_expression",
]
