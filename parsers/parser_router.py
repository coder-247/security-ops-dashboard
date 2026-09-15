import json
import shlex
from pathlib import Path
from typing import Any

from parsers.flask_parser import (
    parse_file as parse_flask_file
)
from parsers.alb_parser import (
    parse_file as parse_alb_file
)
from parsers.cloudtrail_parser import (
    parse_file as parse_cloudtrail_file
)
from parsers.nginx_parser import (
    NGINX_LOG_PATTERN,
    parse_file as parse_nginx_file
)
from parsers.linux_auth_parser import (
    AUTH_LOG_PATTERN,
    parse_file as parse_linux_auth_file
)
from parsers.waf_parser import (
    parse_file as parse_waf_file
)


ALB_CONNECTION_TYPES = {
    "http",
    "https",
    "h2",
    "grpcs",
    "ws",
    "wss"
}


class UnsupportedLogFormatError(Exception):
    """
    지원하지 않는 로그 형식일 때 발생하는 오류입니다.
    """


def read_file_text(
    file_path: str | Path
) -> str:
    path = Path(file_path)

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        return file.read()


def try_load_json(content: str) -> Any | None:
    try:
        return json.loads(content)

    except json.JSONDecodeError:
        return None


def is_cloudtrail_log(data: Any) -> bool:
    if not isinstance(data, dict):
        return False

    records = data.get("Records")

    if not isinstance(records, list):
        return False

    if not records:
        return False

    first_record = records[0]

    if not isinstance(first_record, dict):
        return False

    return (
        "eventSource" in first_record
        and "eventName" in first_record
        and "eventTime" in first_record
    )


def is_waf_record(record: Any) -> bool:
    if not isinstance(record, dict):
        return False

    required_fields = {
        "timestamp",
        "webaclId",
        "action",
        "httpRequest"
    }

    return required_fields.issubset(
        record.keys()
    )


def is_waf_log(data: Any) -> bool:
    if is_waf_record(data):
        return True

    if isinstance(data, list) and data:
        return is_waf_record(data[0])

    return False

def is_flask_record(record: Any) -> bool:
    """
    JSON 객체 한 건이 프로젝트의 Flask 로그인지
    확인합니다.
    """
    if not isinstance(record, dict):
        return False

    required_fields = {
        "timestamp",
        "event_type",
        "action",
        "outcome"
    }

    return required_fields.issubset(
        record.keys()
    )


def is_flask_log(
    content: str,
    json_data: Any
) -> bool:
    """
    단일 JSON 객체와 여러 줄 JSONL을 확인합니다.
    """
    if is_flask_record(json_data):
        return True

    if isinstance(json_data, list) and json_data:
        return is_flask_record(
            json_data[0]
        )

    first_line = get_first_nonempty_line(
        content
    )

    if first_line is None:
        return False

    try:
        first_record = json.loads(
            first_line
        )

    except json.JSONDecodeError:
        return False

    return is_flask_record(
        first_record
    )


def get_first_nonempty_line(
    content: str
) -> str | None:
    for line in content.splitlines():
        if line.strip():
            return line.strip()

    return None


def is_alb_log(content: str) -> bool:
    first_line = get_first_nonempty_line(
        content
    )

    if first_line is None:
        return False

    try:
        fields = shlex.split(first_line)

    except ValueError:
        return False

    if len(fields) < 13:
        return False

    connection_type = fields[0].lower()

    if connection_type not in ALB_CONNECTION_TYPES:
        return False

    timestamp = fields[1]

    return (
        "T" in timestamp
        and timestamp.endswith("Z")
    )


def is_nginx_log(content: str) -> bool:
    """
    첫 번째 로그 줄이 프로젝트의 Nginx 로그 형식과
    일치하는지 확인합니다.
    """
    first_line = get_first_nonempty_line(
        content
    )

    if first_line is None:
        return False

    return (
        NGINX_LOG_PATTERN.match(first_line)
        is not None
    )

def is_linux_auth_log(content: str) -> bool:
    """
    첫 번째 로그 줄이 Linux SSH 인증 로그인지
    확인합니다.
    """
    first_line = get_first_nonempty_line(
        content
    )

    if first_line is None:
        return False

    return (
        AUTH_LOG_PATTERN.match(first_line)
        is not None
    )

def detect_log_type(
    file_path: str | Path
) -> str:
    content = read_file_text(file_path)
    json_data = try_load_json(content)

    if json_data is not None:
        if is_cloudtrail_log(json_data):
            return "cloudtrail"

        if is_waf_log(json_data):
            return "waf"

    if is_flask_log(content, json_data):
        return "flask"
    
    if is_alb_log(content):
        return "alb"

    if is_nginx_log(content):
        return "nginx"

    if is_linux_auth_log(content):
        return "linux_auth"

    raise UnsupportedLogFormatError(
        f"지원하지 않는 로그 형식입니다: {file_path}"
    )


def parse_auto(
    file_path: str | Path
) -> list[dict[str, Any]]:
    log_type = detect_log_type(file_path)

    if log_type == "cloudtrail":
        return parse_cloudtrail_file(file_path)

    if log_type == "waf":
        return parse_waf_file(file_path)

    if log_type == "flask":
        return parse_flask_file(file_path)
    
    if log_type == "alb":
        return parse_alb_file(file_path)

    if log_type == "nginx":
        return parse_nginx_file(file_path)

    if log_type == "linux_auth":
        return parse_linux_auth_file(file_path)
    
    raise UnsupportedLogFormatError(
        f"파서를 찾을 수 없습니다: {log_type}"
    )