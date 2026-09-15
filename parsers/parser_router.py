import json
import shlex
from pathlib import Path
from typing import Any

from parsers.alb_parser import (
    parse_file as parse_alb_file
)
from parsers.cloudtrail_parser import (
    parse_file as parse_cloudtrail_file
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
    """
    JSON과 텍스트 로그를 구분하기 위해
    파일 전체를 문자열로 읽습니다.
    """
    path = Path(file_path)

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        return file.read()


def try_load_json(content: str) -> Any | None:
    """
    문자열이 JSON이면 Python 객체로 변환합니다.
    JSON이 아니면 None을 반환합니다.
    """
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


def get_first_nonempty_line(
    content: str
) -> str | None:
    """
    빈 줄을 제외하고 첫 번째 로그 줄을 가져옵니다.
    """
    for line in content.splitlines():
        if line.strip():
            return line.strip()

    return None


def is_alb_log(content: str) -> bool:
    """
    텍스트가 ALB 액세스 로그인지 확인합니다.

    ALB 로그는 첫 번째 필드가
    http, https, h2, grpcs, ws, wss 중 하나입니다.
    """
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


def detect_log_type(
    file_path: str | Path
) -> str:
    """
    파일 내용을 확인해 로그 종류를 반환합니다.
    """
    content = read_file_text(file_path)
    json_data = try_load_json(content)

    if json_data is not None:
        if is_cloudtrail_log(json_data):
            return "cloudtrail"

        if is_waf_log(json_data):
            return "waf"

    if is_alb_log(content):
        return "alb"

    raise UnsupportedLogFormatError(
        f"지원하지 않는 로그 형식입니다: {file_path}"
    )


def parse_auto(
    file_path: str | Path
) -> list[dict[str, Any]]:
    """
    로그 종류를 자동 판별한 뒤 전용 파서를 실행합니다.
    """
    log_type = detect_log_type(file_path)

    if log_type == "cloudtrail":
        return parse_cloudtrail_file(file_path)

    if log_type == "waf":
        return parse_waf_file(file_path)

    if log_type == "alb":
        return parse_alb_file(file_path)

    raise UnsupportedLogFormatError(
        f"파서를 찾을 수 없습니다: {log_type}"
    )