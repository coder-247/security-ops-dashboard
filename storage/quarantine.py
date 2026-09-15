import hashlib
from datetime import datetime, timezone
from pathlib import Path


def read_original_log(
    file_path: str | Path
) -> str:
    """
    실패한 원본 로그를 안전하게 읽습니다.
    """
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
    같은 오류 로그에 동일한 실패 ID를 부여합니다.
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
    """
    파싱 실패 정보를 대시보드에서 사용할 수 있는
    구조로 만듭니다.
    """
    path = Path(file_path)
    original_log = read_original_log(path)
    error_type = type(error).__name__

    failed_at = (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    return {
        "failure_id": create_failure_id(
            original_log,
            error_type
        ),
        "failed_at": failed_at,
        "status": "quarantined",
        "source_file": str(path),
        "file_name": path.name,
        "detected_log_type": (
            detected_log_type
        ),
        "error_type": error_type,
        "error_message": str(error),
        "retry_count": 0,
        "original_log": original_log
    }