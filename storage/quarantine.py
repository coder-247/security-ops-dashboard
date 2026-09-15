import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def read_original_log(
    file_path: str | Path
) -> str:
    path = Path(file_path)

    try:
        return path.read_text(
            encoding="utf-8",
            errors="replace"
        )

    except OSError:
        return ""


def create_failure_id(
    original_log: str,
    error_type: str
) -> str:
    """
    원본 로그와 오류 종류가 같으면
    항상 같은 실패 ID를 만듭니다.
    """
    source_text = (
        f"{error_type}|{original_log}"
    )

    digest = hashlib.sha256(
        source_text.encode("utf-8")
    ).hexdigest()[:16].upper()

    return f"FAIL-{digest}"


def create_failure_record(
    file_path: str | Path,
    error: Exception,
    detected_log_type: str = "unknown"
) -> dict:
    path = Path(file_path)
    original_log = read_original_log(path)
    error_type = type(error).__name__
    failed_at = utc_now()

    return {
        "failure_id": create_failure_id(
            original_log,
            error_type
        ),
        "failed_at": failed_at,
        "first_seen": failed_at,
        "last_seen": failed_at,
        "status": "quarantined",
        "source_file": str(path),
        "file_name": path.name,
        "detected_log_type": (
            detected_log_type
        ),
        "error_type": error_type,
        "error_message": str(error),
        "occurrence_count": 1,
        "retry_count": 0,
        "last_retry_at": None,
        "resolved_at": None,
        "recovered_event_count": 0,
        "original_log": original_log
    }


def load_failure_records(
    output_file: str | Path
) -> list[dict]:
    """
    기존 격리 JSONL 파일을 읽습니다.
    파일이 아직 없으면 빈 목록을 반환합니다.
    """
    path = Path(output_file)

    if not path.exists():
        return []

    records = []

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        for line in file:
            clean_line = line.strip()

            if not clean_line:
                continue

            try:
                record = json.loads(
                    clean_line
                )

            except json.JSONDecodeError:
                continue

            if isinstance(record, dict):
                records.append(record)

    return records


def merge_failure_records(
    existing_records: list[dict],
    new_records: list[dict]
) -> list[dict]:
    """
    failure_id가 같으면 새 행을 만들지 않고
    기존 기록의 횟수와 마지막 발생시간만 갱신합니다.
    """
    merged_by_id = {
        record["failure_id"]: record.copy()
        for record in existing_records
        if record.get("failure_id")
    }

    for new_record in new_records:
        failure_id = new_record["failure_id"]

        if failure_id in merged_by_id:
            existing = merged_by_id[
                failure_id
            ]

            existing["last_seen"] = (
                new_record["failed_at"]
            )

            existing["failed_at"] = (
                new_record["failed_at"]
            )

            existing["occurrence_count"] = (
                existing.get(
                    "occurrence_count",
                    1
                )
                + 1
            )

            existing["status"] = "quarantined"

            existing["error_type"] = (
                new_record["error_type"]
            )

            existing["error_message"] = (
                new_record["error_message"]
            )

            existing["detected_log_type"] = (
                new_record[
                    "detected_log_type"
                ]
            )

            existing["resolved_at"] = None

        else:
            merged_by_id[failure_id] = (
                new_record.copy()
            )

    return sorted(
        merged_by_id.values(),
        key=lambda record: record.get(
            "first_seen",
            ""
        )
    )


def save_failure_records(
    records: list[dict],
    output_file: str | Path
) -> None:
    """
    격리 목록을 JSONL로 저장합니다.
    """
    path = Path(output_file)

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with path.open(
        "w",
        encoding="utf-8"
    ) as file:
        for record in records:
            json_line = json.dumps(
                record,
                ensure_ascii=False
            )

            file.write(json_line + "\n")