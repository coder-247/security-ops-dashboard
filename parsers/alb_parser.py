import hashlib
import shlex
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


PARSER_NAME = "alb_parser"
PARSER_VERSION = "1.0.0"
MINIMUM_FIELD_COUNT = 29


def to_integer(value: str) -> int | None:
    if value == "-":
        return None

    try:
        return int(value)
    except ValueError:
        return None


def to_float(value: str) -> float | None:
    if value == "-":
        return None

    try:
        return float(value)
    except ValueError:
        return None


def parse_endpoint(
    endpoint: str
) -> tuple[str | None, int | None]:
    """
    203.0.113.50:52341을 IP와 포트로 나눕니다.
    """
    if endpoint == "-":
        return None, None

    try:
        address, port_text = endpoint.rsplit(
            ":",
            1
        )

        return address, int(port_text)

    except (ValueError, AttributeError):
        return endpoint, None


def parse_request(
    request_text: str
) -> dict[str, Any]:
    """
    HTTP 요청을 메서드, URL, 버전으로 나눕니다.

    GET https://example.com/admin HTTP/1.1
    """
    request_parts = request_text.split(
        " ",
        2
    )

    if len(request_parts) != 3:
        return {
            "method": None,
            "url": None,
            "version": None,
            "path": None,
            "query": None
        }

    method, full_url, version = request_parts
    parsed_url = urlparse(full_url)

    return {
        "method": method,
        "url": full_url,
        "version": version,
        "path": parsed_url.path,
        "query": (
            parsed_url.query
            if parsed_url.query
            else None
        )
    }


def calculate_response_time_ms(
    request_processing: float | None,
    target_processing: float | None,
    response_processing: float | None
) -> float | None:
    """
    ALB의 세 처리시간을 더해 밀리초로 변환합니다.
    """
    processing_times = [
        request_processing,
        target_processing,
        response_processing
    ]

    if any(
        value is None
        for value in processing_times
    ):
        return None

    total_seconds = sum(processing_times)

    return round(
        total_seconds * 1000,
        3
    )


def create_event_id(log_line: str) -> str:
    return hashlib.sha256(
        log_line.encode("utf-8")
    ).hexdigest()


def create_tags(
    status_code: int | None,
    url_path: str | None
) -> list[str]:
    tags = [
        "aws",
        "alb",
        "web",
        "http_request"
    ]

    if status_code is not None:
        if 400 <= status_code < 500:
            tags.append("client_error")

        elif status_code >= 500:
            tags.append("server_error")

        else:
            tags.append("success")

    if url_path == "/admin":
        tags.append("admin_page")

    return tags


def parse_line(log_line: str) -> dict[str, Any]:
    """
    ALB 액세스 로그 한 줄을 공통 형식으로 변환합니다.
    """
    clean_line = log_line.strip()

    if not clean_line:
        raise ValueError(
            "ALB 로그가 비어 있습니다."
        )

    fields = shlex.split(clean_line)

    if len(fields) < MINIMUM_FIELD_COUNT:
        raise ValueError(
            "ALB 로그 필드가 부족합니다. "
            f"현재 필드 수: {len(fields)}"
        )

    client_ip, client_port = parse_endpoint(
        fields[3]
    )

    target_ip, target_port = parse_endpoint(
        fields[4]
    )

    request_processing = to_float(fields[5])
    target_processing = to_float(fields[6])
    response_processing = to_float(fields[7])

    status_code = to_integer(fields[8])
    target_status_code = to_integer(fields[9])

    request = parse_request(fields[12])

    event_outcome = (
        "success"
        if status_code is not None
        and status_code < 400
        else "failure"
    )

    return {
        "@timestamp": fields[1],
        "schema_version": "1.0.0",
        "event": {
            "id": create_event_id(clean_line),
            "kind": "event",
            "category": "web",
            "action": "http_request",
            "outcome": event_outcome,
            "severity": 0,
            "severity_label": "informational",
            "risk_score": 0
        },
        "log": {
            "source": "aws_alb",
            "original": clean_line
        },
        "source": {
            "ip": client_ip,
            "port": client_port,
            "cidr": None
        },
        "destination": {
            "ip": target_ip,
            "port": target_port,
            "service": "web"
        },
        "network": {
            "transport": "tcp"
        },
        "user": {
            "name": None
        },
        "http": {
            "method": request["method"],
            "status_code": status_code,
            "target_status_code": (
                target_status_code
            ),
            "user_agent": fields[13],
            "version": request["version"],
            "request_bytes": to_integer(
                fields[10]
            ),
            "response_bytes": to_integer(
                fields[11]
            ),
            "response_time_ms": (
                calculate_response_time_ms(
                    request_processing,
                    target_processing,
                    response_processing
                )
            )
        },
        "url": {
            "full": request["url"],
            "path": request["path"],
            "query": request["query"]
        },
        "cloud": {
            "provider": "aws",
            "service": "elasticloadbalancing",
            "region": "ap-northeast-2",
            "resource_id": fields[2]
        },
        "trace": {
            "id": fields[17]
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
            request["path"]
        )
    }


def parse_file(
    file_path: str | Path
) -> list[dict[str, Any]]:
    """
    ALB 로그 파일의 여러 줄을 모두 파싱합니다.
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
                    f"ALB 로그 {line_number}번째 줄 오류: "
                    f"{error}"
                ) from error

    return events