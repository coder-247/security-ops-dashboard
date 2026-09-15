import json
from pathlib import Path

from detection.rule_engine import detect_events
from parsers.cloudtrail_parser import parse_file


INPUT_FILE = Path(
    "samples/cloudtrail_security_group_open.json"
)

RULES_FILE = Path(
    "detection/rules.yaml"
)

EVENT_OUTPUT_FILE = Path(
    "outputs/normalized/cloudtrail_events.jsonl"
)

ALERT_OUTPUT_FILE = Path(
    "outputs/alerts/cloudtrail_alerts.jsonl"
)


def save_jsonl(
    items: list[dict],
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


def main() -> None:
    print("[1] CloudTrail 로그 읽기")

    events = parse_file(INPUT_FILE)

    print(
        f"[2] 정규화 이벤트: {len(events)}건"
    )

    save_jsonl(
        events,
        EVENT_OUTPUT_FILE
    )

    print("[3] 탐지 규칙 적용")

    alerts = detect_events(
        events,
        RULES_FILE
    )

    save_jsonl(
        alerts,
        ALERT_OUTPUT_FILE
    )

    print(
        f"[4] 생성된 보안 경보: {len(alerts)}건"
    )

    print(
        f"[5] 이벤트 저장: {EVENT_OUTPUT_FILE}"
    )

    print(
        f"[6] 경보 저장: {ALERT_OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()