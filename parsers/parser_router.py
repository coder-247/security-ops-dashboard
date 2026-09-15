import json
from pathlib import Path
from typing import Any

from parsers.cloudtrail_parser import (
    parse_file as parse_cloudtrail_file
)
from parsers.waf_parser import (
    parse_file as parse_waf_file
)


class UnsupportedLogFormatError(Exception):
    """
    지원하지 않는 로그 형식일 때 발생하는 오류입니다.
    """


def load_json(
    file_path: str | Path
) -> Any:
    """
    로그 종류 확인을 위해 JSON 파일을 읽습니다.
    """
    path = Path(file_path)

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def is_cloudtrail_log(data: Any) -> bool:
    """
    CloudTrail 로그인지 확인합니다.
    """
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
    """
    JSON 객체 한 개가 WAF 로그인지 확인합니다.
    """
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
    """
    단일 WAF 객체와 WAF 객체 배열을 모두 확인합니다.
    """
    if is_waf_record(data):
        return True

    if isinstance(data, list) and data:
        return is_waf_record(data[0])

    return False


def detect_log_type(
    file_path: str | Path
) -> str:
    """
    파일 내용을 확인해 로그 종류를 반환합니다.
    """
    data = load_json(file_path)

    if is_cloudtrail_log(data):
        return "cloudtrail"

    if is_waf_log(data):
        return "waf"

    raise UnsupportedLogFormatError(
        f"지원하지 않는 로그 형식입니다: {file_path}"
    )


def parse_auto(
    file_path: str | Path
) -> list[dict[str, Any]]:
    """
    로그 종류를 자동 판별하고 전용 파서를 실행합니다.
    """
    log_type = detect_log_type(file_path)

    if log_type == "cloudtrail":
        return parse_cloudtrail_file(file_path)

    if log_type == "waf":
        return parse_waf_file(file_path)

    raise UnsupportedLogFormatError(
        f"파서를 찾을 수 없습니다: {log_type}"
    )