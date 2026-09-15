import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PARSER_NAME = "linux_auth_parser"
PARSER_VERSION = "1.0.0"


AUTH_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+) "
    r"(?P<hostname>\S+) "
    r"sshd\[(?P<pid>\d+)\]: "
    r"(?P<result>Failed|Accepted) "
    r"password for "
    r"(?P<invalid_user>invalid user )?"
    r"(?P<username>\S+) "
    r"from (?P<source_ip>\S+) "
    r"port (?P<source_port>\d+) "
    r"(?P<protocol>\S+)$"
)


def convert_timestamp(
    timestamp_text: str
) -> str:
    """
    시간대가 포함된 Linux 로그 시간을
    UTC ISO 형식으로 변환합니다.
    """
    try:
        local_time = datetime.fromisoformat(
            timestamp_text
        )

    except ValueError as error:
        raise ValueError(
            "올바르지 않은 Linux 인증 로그 "
            f"시간입니다: {timestamp_text}"
        ) from error

    if local_time.tzinfo is None:
        raise ValueError(
            "Linux 인증 로그 시간에 "
            "시간대가 없습니다."
        )

    utc_time = local_time.astimezone(
        timezone.utc
    )

    return (
        utc_time
        .isoformat()
        .replace("+00:00", "Z")
    )


def create_event_id(log_line: str) -> str:
    return hashlib.sha256(
        log_line.encode("utf-8")
    ).hexdigest()


def create_tags(
    outcome: str,
    invalid_user: bool
) -> list[str]:
    tags = [
        "linux",
        "ssh",
        "authentication"
    ]

    if outcome == "failure":
        tags.append("login_failure")

    else:
        tags.append("login_success")

    if invalid_user:
        tags.append("invalid_user")

    return tags


def parse_line(log_line: str) -> dict[str, Any]:
    """
    SSH 인증 로그 한 줄을 공통 형식으로 변환합니다.
    """
    clean_line = log_line.strip()

    if not clean_line:
        raise ValueError(
            "Linux 인증 로그가 비어 있습니다."
        )

    match = AUTH_LOG_PATTERN.match(
        clean_line
    )

    if not match:
        raise ValueError(
            "지원하지 않는 Linux 인증 로그 형식입니다."
        )

    values = match.groupdict()

    outcome = (
        "failure"
        if values["result"] == "Failed"
        else "success"
    )

    invalid_user = (
        values["invalid_user"] is not None
    )

    return {
        "@timestamp": convert_timestamp(
            values["timestamp"]
        ),
        "schema_version": "1.0.0",
        "event": {
            "id": create_event_id(clean_line),
            "kind": "event",
            "category": "authentication",
            "action": "ssh_login",
            "outcome": outcome,
            "severity": 0,
            "severity_label": "informational",
            "risk_score": 0
        },
        "log": {
            "source": "linux_auth",
            "original": clean_line
        },
        "source": {
            "ip": values["source_ip"],
            "port": int(values["source_port"]),
            "cidr": None
        },
        "destination": {
            "ip": None,
            "port": 22,
            "service": "sshd"
        },
        "network": {
            "transport": "tcp"
        },
        "host": {
            "name": values["hostname"]
        },
        "process": {
            "name": "sshd",
            "pid": int(values["pid"])
        },
        "user": {
            "name": values["username"]
        },
        "http": {
            "method": None,
            "status_code": None,
            "target_status_code": None,
            "user_agent": None,
            "version": None,
            "request_bytes": None,
            "response_bytes": None,
            "response_time_ms": None
        },
        "url": {
            "full": None,
            "path": None,
            "query": None
        },
        "cloud": {
            "provider": "aws",
            "service": "ec2",
            "region": "ap-northeast-2",
            "resource_id": None
        },
        "trace": {
            "id": None
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
            outcome,
            invalid_user
        )
    }


def parse_file(
    file_path: str | Path
) -> list[dict[str, Any]]:
    """
    Linux 인증 로그의 모든 줄을 파싱합니다.
    """
    path = Path(file_path)
    events = []

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        for line_number, line in enumerate(
            file,
            start=1
        ):
            if not line.strip():
                continue

            try:
                event = parse_line(line)
                events.append(event)

            except ValueError as error:
                raise ValueError(
                    f"Linux 인증 로그 "
                    f"{line_number}번째 줄 오류: "
                    f"{error}"
                ) from error

    return events