import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from hacktx_contracts import (
    Event,
    RawEvent,
    SessionSummary,
    Stats,
    parse_event,
    parse_raw_event,
)
from hacktx_contracts.event import CommandEvent
from hacktx_contracts.raw_event import LoginFailRawEvent

CONTRACTS = Path(__file__).resolve().parents[2]
EXAMPLES = CONTRACTS / "examples"
PKG = Path(__file__).resolve().parents[1] / "hacktx_contracts"

MODELS: dict[str, type[BaseModel]] = {
    "event": Event,
    "raw_event": RawEvent,
    "session_summary": SessionSummary,
    "stats": Stats,
}


def validator(name: str) -> Draft202012Validator:
    schema = json.loads((CONTRACTS / f"{name}.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def examples(kind: str):
    files = sorted((EXAMPLES / kind).glob("*.json"))
    assert files, f"no {kind} examples"
    # file names look like <schema>.<case>.json
    return [pytest.param(f.name.split(".")[0], f, id=f.stem) for f in files]


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name,path", examples("valid"))
def test_valid_examples_pass_schema_and_model(name, path):
    data = load(path)
    validator(name).validate(data)
    model = MODELS[name].model_validate(data)
    # dumping the model back out must still match the schema
    validator(name).validate(model.model_dump(mode="json", exclude_unset=True))


@pytest.mark.parametrize("name,path", examples("invalid"))
def test_invalid_examples_fail_schema_and_model(name, path):
    data = load(path)
    assert list(validator(name).iter_errors(data)), "schema accepted a bad example"
    with pytest.raises(ValidationError):
        MODELS[name].model_validate(data)


def test_every_event_type_has_a_valid_example():
    types = validator("event").schema["$defs"]
    pub = {load(p)["type"] for p in (EXAMPLES / "valid").glob("event.*.json")}
    raw = {load(p)["type"] for p in (EXAMPLES / "valid").glob("raw_event.*.json")}
    assert pub == {"session_start", "login_fail", "login_success", "command", "tripwire",
                   "classified", "dossier", "story", "session_end"}
    assert raw == {"session_start", "login_fail", "login_success", "command", "tripwire",
                   "session_end"}
    assert "Geo" in types


def test_parse_helpers_return_typed_variants():
    ev = parse_event((EXAMPLES / "valid" / "event.command.json").read_text(encoding="utf-8"))
    assert isinstance(ev, CommandEvent)
    assert ev.detail.techniques[0].root == "T1087.001"
    raw = parse_raw_event(load(EXAMPLES / "valid" / "raw_event.login_fail.json"))
    assert isinstance(raw, LoginFailRawEvent)
    assert raw.detail.success is False


def property_names(node) -> set[str]:
    names = set()
    if isinstance(node, dict):
        names |= set(node.get("properties", {}))
        for v in node.values():
            names |= property_names(v)
    elif isinstance(node, list):
        for v in node:
            names |= property_names(v)
    return names


def test_schemas_have_no_secret_fields():
    for name in MODELS:
        props = property_names(validator(name).schema)
        assert not {p for p in props if "password" in p}, name
        if name != "raw_event":
            assert "src_ip" not in props, name


def test_generated_models_match_schemas(tmp_path):
    pytest.importorskip("datamodel_code_generator")
    import generate

    for out in generate.generate(tmp_path):
        committed = (PKG / out.name).read_text(encoding="utf-8")
        assert out.read_text(encoding="utf-8") == committed, (
            f"{out.name} is stale, run: python contracts/py/generate.py"
        )
