import hashlib
import json
from pathlib import Path
from typing import Any


PARSER_NAME = "cloudtrail_parser"
PARSER_VERSION = "1.1.0"


def create_event_id(record: dict[str, Any]) -> str:
    event_id = record.get("eventID")

    if event_id:
        return event_id

    original_log = json.dumps(
        record,
        sort_keys=True,
        ensure_ascii=False
    )

    return hashlib.sha256(
        original_log.encode("utf-8")
    ).hexdigest()


def get_service_name(event_source: str) -> str:
    if not event_source:
        return "unknown"

    return event_source.split(".")[0]


def extract_ingress_information(
    request_parameters: dict[str, Any]
) -> dict[str, Any]:
    """
    보안그룹 규칙에서 CIDR, 프로토콜, 포트 정보를 꺼냅니다.
    """
    result = {
        "cidr": None,
        "protocol": None,
        "port": None
    }

    permissions = request_parameters.get(
        "ipPermissions",
        []
    )

    if not permissions:
        return result

    first_permission = permissions[0]

    result["protocol"] = first_permission.get(
        "ipProtocol"
    )

    result["port"] = first_permission.get(
        "fromPort"
    )

    ip_ranges = first_permission.get(
        "ipRanges",
        []
    )

    if ip_ranges:
        result["cidr"] = ip_ranges[0].get(
            "cidrIp"
        )

    return result


def create_tags(record: dict[str, Any]) -> list[str]:
    tags = [
        "aws",
        "cloudtrail",
        "cloud",
        "configuration_change"
    ]

    event_name = record.get("eventName", "")

    if "SecurityGroup" in event_name:
        tags.append("security_group")

    return tags


def parse_record(record: dict[str, Any]) -> dict[str, Any]:
    user_identity = record.get(
        "userIdentity"
    ) or {}

    request_parameters = record.get(
        "requestParameters"
    ) or {}

    ingress = extract_ingress_information(
        request_parameters
    )

    event_source = record.get(
        "eventSource",
        ""
    )

    service_name = get_service_name(
        event_source
    )

    return {
        "@timestamp": record.get("eventTime"),
        "schema_version": "1.0.0",
        "event": {
            "id": create_event_id(record),
            "kind": "event",
            "category": "configuration",
            "action": record.get(
                "eventName",
                "unknown"
            ),
            "outcome": (
                "failure"
                if record.get("errorCode")
                else "success"
            ),
            "severity": 0,
            "severity_label": "informational",
            "risk_score": 0
        },
        "log": {
            "source": "aws_cloudtrail",
            "original": json.dumps(
                record,
                ensure_ascii=False
            )
        },
        "source": {
            "ip": record.get(
                "sourceIPAddress"
            ),
            "port": None,
            "cidr": ingress["cidr"]
        },
        "destination": {
            "ip": None,
            "port": ingress["port"],
            "service": service_name
        },
        "network": {
            "transport": ingress["protocol"]
        },
        "user": {
            "name": (
                user_identity.get("userName")
                or user_identity.get("arn")
            )
        },
        "http": {
            "method": None,
            "status_code": None
        },
        "url": {
            "path": None,
            "query": None
        },
        "cloud": {
            "provider": "aws",
            "service": service_name,
            "region": record.get("awsRegion"),
            "resource_id": request_parameters.get(
                "groupId"
            )
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
        "tags": create_tags(record)
    }


def parse_file(
    file_path: str | Path
) -> list[dict[str, Any]]:
    path = Path(file_path)

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        cloudtrail_data = json.load(file)

    records = cloudtrail_data.get("Records")

    if not isinstance(records, list):
        raise ValueError(
            "CloudTrail 파일에 Records 배열이 없습니다."
        )

    return [
        parse_record(record)
        for record in records
    ]