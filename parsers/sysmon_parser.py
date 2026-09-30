import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any


PARSER_NAME = "sysmon_parser"
PARSER_VERSION = "1.0.0"
SYSMON_CHANNEL = (
    "Microsoft-Windows-Sysmon/Operational"
)


def normalize_timestamp(value: str) -> str:
    """
    Sysmon UTC 시간이나 ISO 시간을 UTC ISO 형식으로 변환합니다.
    """
    if not value:
        raise ValueError(
            "Sysmon 이벤트에 시간이 없습니다."
        )

    normalized = value.strip().replace(" ", "T")

    if normalized.endswith("Z"):
        parsed = datetime.fromisoformat(
            normalized.replace("Z", "+00:00")
        )
    else:
        parsed = datetime.fromisoformat(
            normalized
        ).replace(tzinfo=timezone.utc)

    return (
        parsed.astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def to_integer(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_user(value: str | None) -> dict:
    if not value or value == "-":
        return {
            "name": None,
            "domain": None
        }

    if "\\" in value:
        domain, name = value.split("\\", 1)
        return {
            "name": name,
            "domain": domain
        }

    return {
        "name": value,
        "domain": None
    }


def parse_hashes(value: str | None) -> dict:
    hashes = {}

    if not value:
        return hashes

    for item in value.split(","):
        if "=" not in item:
            continue

        algorithm, hash_value = item.split(
            "=",
            1
        )

        hashes[
            algorithm.strip().lower()
        ] = hash_value.strip().lower()

    return hashes


def create_event_id(raw_event: dict) -> str:
    canonical_event = json.dumps(
        raw_event,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(
        canonical_event.encode("utf-8")
    ).hexdigest()


def create_tags(
    image: str,
    command_line: str
) -> list[str]:
    tags = [
        "windows",
        "endpoint",
        "edr",
        "sysmon",
        "process_creation"
    ]

    image_lower = image.lower()
    command_lower = command_line.lower()

    if image_lower.endswith(
        ("powershell.exe", "pwsh.exe")
    ):
        tags.append("powershell")

    encoded_options = (
        "-encodedcommand",
        "-enc ",
        "-e "
    )

    if any(
        option in command_lower
        for option in encoded_options
    ):
        tags.extend([
            "encoded_command",
            "suspicious_powershell"
        ])

    return tags


def parse_event(
    raw_event: dict[str, Any]
) -> dict[str, Any]:
    winlog = raw_event.get("winlog")

    if not isinstance(winlog, dict):
        raise ValueError(
            "winlog 객체가 없는 Sysmon 로그입니다."
        )

    event_id = to_integer(
        winlog.get("event_id")
    )

    if event_id != 1:
        raise ValueError(
            "현재 파서는 Sysmon Event ID 1만 지원합니다."
        )

    event_data = winlog.get(
        "event_data"
    )

    if not isinstance(event_data, dict):
        raise ValueError(
            "winlog.event_data가 없습니다."
        )

    image = event_data.get("Image", "")
    command_line = event_data.get(
        "CommandLine",
        ""
    )

    if not image:
        raise ValueError(
            "Sysmon Image 필드가 없습니다."
        )

    timestamp = (
        raw_event.get("@timestamp")
        or event_data.get("UtcTime")
    )

    process_name = PureWindowsPath(
        image
    ).name

    parent_image = event_data.get(
        "ParentImage"
    )

    parent_name = (
        PureWindowsPath(parent_image).name
        if parent_image
        else None
    )

    user = parse_user(
        event_data.get("User")
    )

    hashes = parse_hashes(
        event_data.get("Hashes")
    )

    original = json.dumps(
        raw_event,
        ensure_ascii=False,
        sort_keys=True
    )

    return {
        "@timestamp": normalize_timestamp(
            timestamp
        ),
        "schema_version": "1.0.0",
        "event": {
            "id": create_event_id(raw_event),
            "kind": "event",
            "category": "process",
            "action": "process_start",
            "outcome": "success",
            "severity": 0,
            "severity_label": "informational",
            "risk_score": 0,
            "code": str(event_id)
        },
        "log": {
            "source": "windows_sysmon",
            "original": original
        },
        "host": {
            "name": winlog.get(
                "computer_name"
            ),
            "os": {
                "type": "windows"
            }
        },
        "user": user,
        "process": {
            "pid": to_integer(
                event_data.get("ProcessId")
            ),
            "entity_id": event_data.get(
                "ProcessGuid"
            ),
            "name": process_name,
            "executable": image,
            "command_line": command_line,
            "working_directory": (
                event_data.get(
                    "CurrentDirectory"
                )
            ),
            "hash": hashes,
            "parent": {
                "pid": to_integer(
                    event_data.get(
                        "ParentProcessId"
                    )
                ),
                "entity_id": event_data.get(
                    "ParentProcessGuid"
                ),
                "name": parent_name,
                "executable": parent_image,
                "command_line": (
                    event_data.get(
                        "ParentCommandLine"
                    )
                )
            }
        },
        "windows": {
            "channel": winlog.get(
                "channel",
                SYSMON_CHANNEL
            ),
            "event_id": event_id,
            "record_id": winlog.get(
                "record_id"
            ),
            "integrity_level": (
                event_data.get(
                    "IntegrityLevel"
                )
            ),
            "logon_id": event_data.get(
                "LogonId"
            )
        },
        "source": {
            "ip": None,
            "port": None,
            "cidr": None
        },
        "destination": {
            "ip": None,
            "port": None,
            "service": None
        },
        "cloud": {
            "provider": None,
            "service": None,
            "region": None,
            "resource_id": None
        },
        "trace": {
            "id": event_data.get(
                "ProcessGuid"
            )
        },
        "rule": {
            "id": None,
            "name": None,
            "description": None,
            "recommendation": None
        },
        "parser": {
            "name": PARSER_NAME,
            "version": PARSER_VERSION,
            "status": "success"
        },
        "tags": create_tags(
            image,
            command_line
        )
    }


def parse_file(
    file_path: str | Path
) -> list[dict[str, Any]]:
    path = Path(file_path)

    try:
        with path.open(
            "r",
            encoding="utf-8"
        ) as file:
            raw_data = json.load(file)

    except json.JSONDecodeError as error:
        raise ValueError(
            "올바르지 않은 Sysmon JSON입니다."
        ) from error

    raw_events = (
        raw_data
        if isinstance(raw_data, list)
        else [raw_data]
    )

    return [
        parse_event(raw_event)
        for raw_event in raw_events
    ]