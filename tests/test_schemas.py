import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from authz_analyzer import (
    explain_document,
    load_document,
    report_document,
    result_to_data,
)

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize(
    ("schema_name", "example_name"),
    [
        ("boolean-ir-v1.schema.json", "pii-access.json"),
        ("boolean-ir-v1.schema.json", "policy-diff.json"),
        ("result-v1.schema.json", "pii-access.verify-result.json"),
        ("result-v1.schema.json", "policy-diff.result.json"),
    ],
)
def test_published_schema_accepts_example(schema_name: str, example_name: str) -> None:
    schema = json.loads((ROOT / "schemas" / schema_name).read_text())
    example = json.loads((ROOT / "examples" / example_name).read_text())

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(example)


def test_widened_diff_cannot_include_removed_access() -> None:
    validator = _result_validator()
    result = json.loads((ROOT / "examples" / "policy-diff.result.json").read_text())
    result["removedAccess"] = result["addedAccess"]

    with pytest.raises(ValidationError):
        validator.validate(result)


def test_narrowed_diff_cannot_include_added_access() -> None:
    validator = _result_validator()
    result = json.loads((ROOT / "examples" / "policy-diff.result.json").read_text())
    result["classification"] = "narrowed"
    result["removedAccess"] = result.pop("addedAccess")
    result["addedAccess"] = result["removedAccess"]

    with pytest.raises(ValidationError):
        validator.validate(result)


def test_minimal_positive_explanation_cannot_contain_false_literals() -> None:
    validator = _result_validator()
    result = {
        "resultVersion": "1",
        "kind": "explain",
        "status": "completed",
        "target": "access",
        "explanations": [
            {
                "minimality": "minimal-positive",
                "literals": [{"atom": "ADMIN", "value": False}],
            }
        ],
        "truncated": False,
    }

    with pytest.raises(ValidationError):
        validator.validate(result)


def test_published_schema_accepts_generated_report() -> None:
    document = load_document((ROOT / "examples" / "pii-access.json").read_bytes())
    report = report_document(document)

    _result_validator().validate(result_to_data(report))


def test_published_schema_accepts_generated_explanations() -> None:
    document = load_document((ROOT / "examples" / "pii-access.json").read_bytes())
    result = explain_document(document, "user.ssn")

    _result_validator().validate(result_to_data(result))


def test_verify_example_uses_the_normative_default_variable_order() -> None:
    result = json.loads(
        (ROOT / "examples" / "pii-access.verify-result.json").read_text()
    )

    assert result["diagnostics"]["variableOrder"] == [
        "ADMIN",
        "EMPLOYEE",
        "PII_READ",
        "SUPPORT_OVERRIDE",
        "INCIDENT_OPEN",
    ]


def _result_validator() -> Draft202012Validator:
    schema = json.loads((ROOT / "schemas" / "result-v1.schema.json").read_text())
    return Draft202012Validator(schema)
