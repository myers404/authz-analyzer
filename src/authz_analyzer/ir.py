from __future__ import annotations

from dataclasses import dataclass

from authz_analyzer.expressions import Expression

type JSONValue = (
    None | bool | int | float | str | list[JSONValue] | dict[str, JSONValue]
)


@dataclass(slots=True)
class Provenance:
    source: str | None = None
    line: int | None = None
    column: int | None = None
    pointer: str | None = None
    symbol: str | None = None
    note: str | None = None


@dataclass(slots=True)
class AtomMetadata:
    description: str | None = None
    category: str | None = None
    owner: str | None = None
    tags: tuple[str, ...] | None = None
    provenance: tuple[Provenance, ...] | None = None
    extensions: dict[str, JSONValue] | None = None


@dataclass(slots=True)
class DocumentMetadata:
    title: str | None = None
    description: str | None = None
    extensions: dict[str, JSONValue] | None = None


@dataclass(slots=True)
class IRDocument:
    expressions: dict[str, Expression]
    ir_version: str = "1"
    atoms: dict[str, AtomMetadata] | None = None
    requirements: dict[str, Expression] | None = None
    assumptions: tuple[Expression, ...] | None = None
    metadata: DocumentMetadata | None = None


__all__ = [
    "AtomMetadata",
    "DocumentMetadata",
    "IRDocument",
    "JSONValue",
    "Provenance",
]
