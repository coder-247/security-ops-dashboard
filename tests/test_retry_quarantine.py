from pathlib import Path

from retry_quarantine import (
    retry_failure_record,
    retry_quarantined_records
)
from storage.quarantine import (
    create_failure_record
)


VALID_NGINX_LINE = (
    '203.0.113.77 - - '
    '[16/Sep/2026:11:20:00 +0900] '
    '"GET /login HTTP/1.1" '
    '200 256 "-" "test-client/1.0" '
    'request_time=0.020 '
    'request_id=test-retry-file'
)

INVALID_NGINX_CONTENT = (
    VALID_NGINX_LINE
    + "\n"
    + "this is an invalid nginx log"
    + "\n"
)


def create_temporary_failure(
    tmp_path: Path
) -> tuple[Path, dict]:
    """
    테스트용 오류 파일과 격리 기록을 만듭니다.
    """
    log_file = (
        tmp_path
        / "retry_nginx.log"
    )

    log_file.write_text(
        INVALID_NGINX_CONTENT,
        encoding="utf-8"
    )

    failure_record = create_failure_record(
        log_file,
        ValueError("테스트 파싱 실패"),
        "nginx"
    )

    return log_file, failure_record


def test_failed_retry_remains_quarantined(
    tmp_path: Path
):
    """
    원본 로그가 여전히 잘못돼 있으면
    격리 상태를 유지하는지 확인합니다.
    """
    _, failure_record = (
        create_temporary_failure(
            tmp_path
        )
    )

    updated_record, recovered_events = (
        retry_failure_record(
            failure_record
        )
    )

    assert updated_record["status"] == (
        "quarantined"
    )

    assert updated_record["retry_count"] == 1

    assert updated_record[
        "recovered_event_count"
    ] == 0

    assert updated_record[
        "last_retry_error_type"
    ] == "ValueError"

    assert updated_record[
        "last_retry_error_message"
    ]

    assert recovered_events == []


def test_repaired_log_becomes_resolved(
    tmp_path: Path
):
    """
    격리 후 원본 로그를 수정하면
    재처리에 성공하는지 확인합니다.
    """
    log_file, failure_record = (
        create_temporary_failure(
            tmp_path
        )
    )

    # 잘못된 두 번째 줄을 제거하여
    # 원본 파일을 정상 상태로 고칩니다.
    log_file.write_text(
        VALID_NGINX_LINE + "\n",
        encoding="utf-8"
    )

    updated_record, recovered_events = (
        retry_failure_record(
            failure_record
        )
    )

    assert updated_record["status"] == (
        "resolved"
    )

    assert updated_record["retry_count"] == 1

    assert updated_record["resolved_at"]

    assert updated_record[
        "recovered_event_count"
    ] == 1

    assert updated_record[
        "last_retry_error_type"
    ] is None

    assert updated_record[
        "last_retry_error_message"
    ] is None

    assert len(recovered_events) == 1

    recovered_event = recovered_events[0]

    assert recovered_event["log"]["source"] == (
        "nginx_access"
    )

    assert recovered_event["source"]["ip"] == (
        "203.0.113.77"
    )

    assert recovered_event["url"]["path"] == (
        "/login"
    )

    assert recovered_event["http"][
        "status_code"
    ] == 200


def test_resolved_record_is_not_retried(
    tmp_path: Path
):
    """
    이미 해결된 기록은 다시 처리하지 않고
    retry_count도 증가시키지 않는지 확인합니다.
    """
    log_file, failure_record = (
        create_temporary_failure(
            tmp_path
        )
    )

    log_file.write_text(
        VALID_NGINX_LINE + "\n",
        encoding="utf-8"
    )

    failure_record["status"] = "resolved"
    failure_record["retry_count"] = 2

    updated_records, recovered_events = (
        retry_quarantined_records(
            [failure_record]
        )
    )

    assert len(updated_records) == 1

    updated_record = updated_records[0]

    assert updated_record["status"] == (
        "resolved"
    )

    assert updated_record["retry_count"] == 2

    assert recovered_events == []