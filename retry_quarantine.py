import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from parsers.parser_router import (
    detect_log_type,
    parse_auto
)
from storage.quarantine import (
    load_failure_records,
    save_failure_records
)


QUARANTINE_FILE = Path(
    "outputs/quarantine/failed_logs.jsonl"
)

RECOVERED_EVENTS_FILE = Path(
    "outputs/recovered/recovered_events.jsonl"
)


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def save_jsonl(
    items: list[dict[str, Any]],
    output_file: Path
) -> None:
    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as file:
        for item in items:
            json_line = json.dumps(
                item,
                ensure_ascii=False
            )

            file.write(json_line + "\n")


def retry_failure_record(
    failure_record: dict[str, Any]
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]]
]:
    """
    격리 기록 한 건의 원본 파일을 다시 파싱합니다.
    """
    updated_record = deepcopy(
        failure_record
    )

    updated_record["retry_count"] = (
        updated_record.get(
            "retry_count",
            0
        )
        + 1
    )

    updated_record["last_retry_at"] = (
        utc_now()
    )

    source_file = updated_record.get(
        "source_file"
    )

    if not source_file:
        updated_record["status"] = (
            "quarantined"
        )

        updated_record[
            "last_retry_error_type"
        ] = "MissingSourceFile"

        updated_record[
            "last_retry_error_message"
        ] = (
            "격리 기록에 source_file이 없습니다."
        )

        return updated_record, []

    try:
        detected_log_type = detect_log_type(
            source_file
        )

        recovered_events = parse_auto(
            source_file
        )

        updated_record[
            "detected_log_type"
        ] = detected_log_type

        updated_record["status"] = "resolved"

        updated_record["resolved_at"] = (
            utc_now()
        )

        updated_record[
            "recovered_event_count"
        ] = len(recovered_events)

        updated_record[
            "last_retry_error_type"
        ] = None

        updated_record[
            "last_retry_error_message"
        ] = None

        return (
            updated_record,
            recovered_events
        )

    except Exception as error:
        updated_record["status"] = (
            "quarantined"
        )

        updated_record["resolved_at"] = None

        updated_record[
            "recovered_event_count"
        ] = 0

        updated_record[
            "last_retry_error_type"
        ] = type(error).__name__

        updated_record[
            "last_retry_error_message"
        ] = str(error)

        return updated_record, []


def retry_quarantined_records(
    records: list[dict[str, Any]]
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]]
]:
    """
    quarantined 상태인 기록만 재처리합니다.
    resolved 상태는 다시 처리하지 않습니다.
    """
    updated_records = []
    recovered_events = []

    for record in records:
        if record.get("status") != (
            "quarantined"
        ):
            updated_records.append(record)
            continue

        updated_record, events = (
            retry_failure_record(record)
        )

        updated_records.append(
            updated_record
        )

        recovered_events.extend(events)

    return (
        updated_records,
        recovered_events
    )


def main() -> None:
    print("[1] 격리 기록 읽기")

    records = load_failure_records(
        QUARANTINE_FILE
    )

    quarantined_count = sum(
        1
        for record in records
        if record.get("status")
        == "quarantined"
    )

    print(
        f"    전체 격리 기록: "
        f"{len(records)}건"
    )

    print(
        f"    재처리 대상: "
        f"{quarantined_count}건"
    )

    if quarantined_count == 0:
        print("[2] 재처리할 로그가 없습니다.")
        return

    print("[2] 격리 로그 재처리")

    updated_records, recovered_events = (
        retry_quarantined_records(records)
    )

    save_failure_records(
        updated_records,
        QUARANTINE_FILE
    )

    save_jsonl(
        recovered_events,
        RECOVERED_EVENTS_FILE
    )

    resolved_count = sum(
        1
        for record in updated_records
        if record.get("status") == "resolved"
    )

    remaining_count = sum(
        1
        for record in updated_records
        if record.get("status")
        == "quarantined"
    )

    print(
        f"[3] 복구된 이벤트: "
        f"{len(recovered_events)}건"
    )

    print(
        f"[4] 해결된 격리 기록: "
        f"{resolved_count}건"
    )

    print(
        f"[5] 아직 실패 상태: "
        f"{remaining_count}건"
    )

    print(
        f"[6] 복구 이벤트 저장: "
        f"{RECOVERED_EVENTS_FILE}"
    )


if __name__ == "__main__":
    main()