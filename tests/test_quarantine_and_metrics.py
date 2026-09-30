import json
from pathlib import Path
import statistics

from main import (
    collect_and_parse,
    save_json
)
from storage.quarantine import (
    create_failure_record
)


PROJECT_ROOT = Path(__file__).parent.parent

INVALID_LOG_FILE = (
    PROJECT_ROOT
    / "samples"
    / "nginx_with_invalid_line.log"
)


def test_failure_record_contains_error_details():
    """
    실패 기록에 업무상 필요한 정보가
    모두 들어가는지 확인합니다.
    """
    test_error = ValueError(
        "테스트 파싱 오류"
    )

    failure = create_failure_record(
        INVALID_LOG_FILE,
        test_error,
        "nginx"
    )

    assert failure["failure_id"].startswith(
        "FAIL-"
    )

    assert failure["status"] == "quarantined"

    assert failure["file_name"] == (
        "nginx_with_invalid_line.log"
    )

    assert failure["detected_log_type"] == (
        "nginx"
    )

    assert failure["error_type"] == (
        "ValueError"
    )

    assert failure["error_message"] == (
        "테스트 파싱 오류"
    )

    assert failure["retry_count"] == 0
    assert failure["original_log"]


def test_same_failure_has_same_failure_id():
    """
    같은 원본 로그와 오류 유형에는
    동일한 실패 ID가 생성되는지 확인합니다.
    """
    first_failure = create_failure_record(
        INVALID_LOG_FILE,
        ValueError("첫 번째 메시지"),
        "nginx"
    )

    second_failure = create_failure_record(
        INVALID_LOG_FILE,
        ValueError("두 번째 메시지"),
        "nginx"
    )

    assert (
        first_failure["failure_id"]
        == second_failure["failure_id"]
    )


def test_pipeline_continues_after_failure():
    """
    잘못된 파일이 있어도 정상 파일의 이벤트가
    계속 처리되는지 확인합니다.
    """
    events, failures, statistics = (
        collect_and_parse()
    )

    assert len(events) == 11
    assert len(failures) == 1

    assert statistics["successful_files"] == 7
    assert statistics["total_events"] == 11
    assert statistics["failed_files"] == 1


def test_parsing_statistics_are_correct():
    """
    성공률과 실패율 계산이 정확한지 확인합니다.
    """
    events, failures, statistics = (
        collect_and_parse()
    )

    assert statistics["total_files"] == 8
    assert statistics["successful_files"] == 7
    assert statistics["failed_files"] == 1
    assert statistics["total_events"] == 11

    assert statistics[
         "parse_success_rate"
    ] == 87.5

    assert statistics[
        "parse_failure_rate"
    ] == 12.5

    assert statistics["generated_at"].endswith(
        "Z"
    )


def test_statistics_are_saved_as_json(
    tmp_path: Path
):
    """
    통계가 정상적인 JSON 파일로
    저장되는지 확인합니다.
    """
    statistics = {
        "total_files": 8,
        "successful_files": 7,
        "failed_files": 1,
        "total_events": 11,
        "parse_success_rate": 87.5,
        "parse_failure_rate": 12.5
    }

    output_file = (
        tmp_path
        / "parsing_statistics.json"
    )

    save_json(
        statistics,
        output_file
    )

    assert output_file.exists()

    saved_data = json.loads(
        output_file.read_text(
            encoding="utf-8"
        )
    )

    assert saved_data["total_files"] == 8

    assert saved_data[
        "parse_success_rate"
    ] == 87.5

    assert saved_data[
        "parse_failure_rate"
    ] == 12.5