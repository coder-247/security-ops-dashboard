import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


PARSER_NAME = "nginx_parser"
PARSER_VERSION = "1.0.0"


NGINX_LOG_PATTERN = re.compile(
    r'^(?P<source_ip>\S+) '
    r'(?P<identity>\S+) '
    r'(?P<user>\S+) '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) '
    r'(?P<url>\S+) '
    r'(?P<http_version>[^"]+)" '
    r'(?P<status_code>\d{3}) '
    r'(?P<response_bytes>\S+) '
    r'"(?P<referrer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)" '
    r'request_time=(?P<request_time>\S+) '
    r'request_id=(?P<request_id>\S+)$'
)


MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12
}


def convert_nginx_timestamp(
    timestamp_text: str
) -> str:
    """
    Nginx 시간을 UTC ISO 형식으로 변환합니다.

    16/Sep/2026:11:00:00 +0900
    → 2026-09-16T02:00:00Z
    """
    timestamp_pattern = re.compile(
        r"^(?P<day>\d{2})/"
        r"(?P<month>[A-Za-z]{3})/"
        r"(?P<year>\d{4}):"
        r"(?P<hour>\d{2}):"
        r"(?P<minute>\d{2}):"
        r"(?P<second>\d{2}) "
        r"(?P<offset_sign>[+-])"
        r"(?P<offset_hour>\d{2})"
        r"(?P<offset_minute>\d{2})$"
    )

    match = timestamp_pattern.match(
        timestamp_text
    )

    if not match:
        raise ValueError(
            "올바르지 않은 Nginx 시간 형식입니다: "
            f"{timestamp_text}"
        )

    values = match.groupdict()
    month = MONTHS.get(values["month"])

    if month is None:
        raise ValueError(
            f"알 수 없는 월입니다: {values['month']}"
        )

    offset_minutes = (
        int(values["offset_hour"]) * 60
        + int(values["offset_minute"])
    )

    if values["offset_sign"] == "-":
        offset_minutes *= -1

    local_timezone = timezone(
        timedelta(minutes=offset_minutes)
    )

    local_time = datetime(
        year=int(values["year"]),
        month=month,
        day=int(values["day"]),
        hour=int(values["hour"]),
        minute=int(values["minute"]),
        second=int(values["second"]),
        tzinfo=local_timezone
    )

    utc_time = local_time.astimezone(
        timezone.utc
    )

    return (
        utc_time
        .isoformat()
        .replace("+00:00", "Z")
    )


def to_integer(value: str) -> int | None:
    if value == "-":
        return None

    try:
        return int(value)
    except ValueError:
        return None


def to_milliseconds(value: str) -> float | None:
    if value == "-":
        return None

    try:
        seconds = float(value)
        return round(seconds * 1000, 3)

    except ValueError:
        return None


def create_event_id(
    log_line: str,
    request_id: str
) -> str:
    """
    요청 ID가 있으면 이벤트 ID로 사용합니다.
    없으면 로그 내용의 SHA-256 해시를 사용합니다.
    """
    if request_id and request_id != "-":
        return request_id

    return hashlib.sha256(
        log_line.encode("utf-8")
    ).hexdigest()


def create_tags(
    status_code: int,
    url_path: str
) -> list[str]:
    tags = [
        "linux",
        "nginx",
        "web",
        "http_request"
    ]

    if 400 <= status_code < 500:
        tags.append("client_error")

    elif status_code >= 500:
        tags.append("server_error")

    else:
        tags.append("success")

    if url_path == "/admin":
        tags.append("admin_page")

    if status_code == 401:
        tags.append("authentication_failure")

    return tags


def parse_line(log_line: str) -> dict[str, Any]:
    """
    Nginx 로그 한 줄을 공통 형식으로 변환합니다.
    """
    clean_line = log_line.strip()

    if not clean_line:
        raise ValueError(
            "Nginx 로그가 비어 있습니다."
        )

    match = NGINX_LOG_PATTERN.match(
        clean_line
    )

    if not match:
        raise ValueError(
            "지원하지 않는 Nginx 로그 형식입니다."
        )

    values = match.groupdict()

    status_code = int(
        values["status_code"]
    )

    parsed_url = urlparse(
        values["url"]
    )

    url_path = parsed_url.path
    request_id = values["request_id"]

    event_outcome = (
        "success"
        if status_code < 400
        else "failure"
    )

    user_name = (
        None
        if values["user"] == "-"
        else values["user"]
    )

    return {
        "@timestamp": convert_nginx_timestamp(
            values["timestamp"]
        ),
        "schema_version": "1.0.0",
        "event": {
            "id": create_event_id(
                clean_line,
                request_id
            ),
            "kind": "event",
            "category": "web",
            "action": "http_request",
            "outcome": event_outcome,
            "severity": 0,
            "severity_label": "informational",
            "risk_score": 0
        },
        "log": {
            "source": "nginx_access",
            "original": clean_line
        },
        "source": {
            "ip": values["source_ip"],
            "port": None,
            "cidr": None
        },
        "destination": {
            "ip": None,
            "port": 443,
            "service": "nginx"
        },
        "network": {
            "transport": "tcp"
        },
        "user": {
            "name": user_name
        },
        "http": {
            "method": values["method"],
            "status_code": status_code,
            "target_status_code": None,
            "user_agent": values["user_agent"],
            "version": values["http_version"],
            "request_bytes": None,
            "response_bytes": to_integer(
                values["response_bytes"]
            ),
            "response_time_ms": (
                to_milliseconds(
                    values["request_time"]
                )
            )
        },
        "url": {
            "full": values["url"],
            "path": url_path,
            "query": (
                parsed_url.query
                if parsed_url.query
                else None
            )
        },
        "cloud": {
            "provider": "aws",
            "service": "ec2",
            "region": "ap-northeast-2",
            "resource_id": None
        },
        "trace": {
            "id": (
                None
                if request_id == "-"
                else request_id
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
            status_code,
            url_path
        )
    }


def parse_file(
    file_path: str | Path
) -> list[dict[str, Any]]:
    """
    Nginx 로그 파일의 여러 줄을 모두 파싱합니다.
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
                    f"Nginx 로그 {line_number}번째 줄 오류: "
                    f"{error}"
                ) from error

    return events