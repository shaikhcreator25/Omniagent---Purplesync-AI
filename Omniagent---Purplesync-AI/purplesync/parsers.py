"""Parse and validate Red Team tests and Blue Team logs from CSV/JSON."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from pydantic import ValidationError

from purplesync.models import BlueTeamLog, RedTeamTest

MAX_UPLOAD_BYTES = 2_000_000
MAX_ROWS = 500

_RED_ALIASES = {
    "test_id": {"test_id", "id", "testid", "test #", "test"},
    "name": {"name", "scenario", "test_name", "title"},
    "description": {"description", "details", "notes"},
    "technique_id": {"technique_id", "mitre", "mitre_id", "attack_id", "technique"},
    "expected_detection": {
        "expected_detection",
        "expected",
        "detection",
        "alert",
        "rule",
        "ids_rule",
    },
    "keywords": {"keywords", "keyword", "indicators"},
    "asset_id": {"asset_id", "asset", "hostname", "device_id"},
    "executed_at": {"executed_at", "test_time", "run_time", "timestamp"},
    "time_window_minutes": {"time_window_minutes", "window_minutes"},
}

_BLUE_ALIASES = {
    "timestamp": {"timestamp", "time", "event_time", "@timestamp"},
    "source": {"source", "host", "device", "index"},
    "alert_name": {"alert_name", "alert", "signature", "title", "event_name"},
    "technique_id": {"technique_id", "mitre", "mitre_id", "attack_id", "technique"},
    "message": {"message", "raw", "description", "details"},
    "severity": {"severity", "level", "priority"},
    "rule_id": {"rule_id", "rule", "sid", "detection_id"},
    "asset_id": {"asset_id", "asset", "hostname", "device_id"},
}


class ParseError(ValueError):
    pass


def _validation_message(exc: ValidationError) -> str:
    first = exc.errors(include_input=False)[0]
    field = ".".join(str(part) for part in first.get("loc", ())) or "record"
    message = str(first.get("msg", "invalid value")).replace("Value error, ", "", 1)
    return f"{field}: {message}"


def _ensure_size(payload: bytes | str) -> str:
    if isinstance(payload, bytes):
        if len(payload) > MAX_UPLOAD_BYTES:
            raise ParseError("Uploaded file exceeds 2 MB limit")
        try:
            return payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ParseError("File must be UTF-8 text") from exc
    if len(payload.encode("utf-8")) > MAX_UPLOAD_BYTES:
        raise ParseError("Uploaded file exceeds 2 MB limit")
    return payload


def _map_row(row: dict[str, Any], aliases: dict[str, set[str]]) -> dict[str, Any]:
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    mapped: dict[str, Any] = {}
    for field, names in aliases.items():
        for name in names:
            if name in lowered and lowered[name] not in (None, ""):
                mapped[field] = lowered[name]
                break
    return mapped


def _load_records(text: str) -> list[dict[str, Any]]:
    stripped = text.strip()
    if not stripped:
        raise ParseError("File is empty")
    if stripped[0] in "[{":
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON: {exc.msg}") from exc
        if isinstance(data, dict):
            for key in ("tests", "logs", "records", "data", "items"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
            else:
                data = [data]
        if not isinstance(data, list):
            raise ParseError("JSON must be a list of records or an object with a list")
        if any(not isinstance(item, dict) for item in data):
            raise ParseError("Every JSON record must be an object")
        return data

    reader = csv.DictReader(io.StringIO(stripped))
    if not reader.fieldnames:
        raise ParseError("CSV is missing a header row")
    return list(reader)


def parse_red_team(payload: bytes | str) -> list[RedTeamTest]:
    records = _load_records(_ensure_size(payload))
    if len(records) > MAX_ROWS:
        raise ParseError(f"Too many rows (max {MAX_ROWS})")
    tests: list[RedTeamTest] = []
    seen_ids: set[str] = set()
    for i, raw in enumerate(records, start=1):
        mapped = _map_row(raw, _RED_ALIASES)
        if "test_id" not in mapped:
            mapped["test_id"] = str(raw.get("test_id") or f"RT-{i:03d}")
        if "name" not in mapped:
            mapped["name"] = str(
                raw.get("name") or mapped.get("description") or mapped["test_id"]
            )
        if "expected_detection" not in mapped:
            raise ParseError(f"Row {i} is missing expected_detection")
        try:
            test = RedTeamTest.model_validate(mapped)
        except ValidationError as exc:
            raise ParseError(f"Row {i} is invalid: {_validation_message(exc)}") from exc
        if test.test_id in seen_ids:
            raise ParseError(f"Duplicate test_id: {test.test_id}")
        seen_ids.add(test.test_id)
        tests.append(test)
    return tests


def parse_blue_team(payload: bytes | str) -> list[BlueTeamLog]:
    records = _load_records(_ensure_size(payload))
    if len(records) > MAX_ROWS:
        raise ParseError(f"Too many rows (max {MAX_ROWS})")
    logs: list[BlueTeamLog] = []
    for i, raw in enumerate(records, start=1):
        mapped = _map_row(raw, _BLUE_ALIASES)
        if not any(mapped.get(k) for k in ("alert_name", "message", "rule_id")):
            raise ParseError(f"Row {i} has no alert_name, message, or rule_id")
        try:
            logs.append(BlueTeamLog.model_validate(mapped))
        except ValidationError as exc:
            raise ParseError(f"Row {i} is invalid: {_validation_message(exc)}") from exc
    return logs
