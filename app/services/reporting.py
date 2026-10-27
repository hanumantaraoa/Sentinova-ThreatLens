import csv
import io
import json
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.all_models import Indicator, IOCType, TLPMarking, AuditLog


def convert_tlp_to_stix(tlp_marking: TLPMarking) -> str:
    """Maps internal database TLP enumerations to canonical STIX 2.1 marking definitions."""
    tlp_map = {
        TLPMarking.CLEAR: "marking-definition--613f2e26-407d-48c7-9ece-b7e992d9316e",
        TLPMarking.GREEN: "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        TLPMarking.AMBER: "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        TLPMarking.RED: "marking-definition--5e57c739-ab7e-4679-b6d3-de4092ca9040",
    }
    return tlp_map.get(tlp_marking, tlp_map[TLPMarking.CLEAR])


def convert_type_to_stix_pattern(ioc_type: IOCType, value: str) -> str:
    """Translates database column categories into explicit STIX 2.1 cyber observable patterns."""
    if ioc_type == IOCType.IP:
        return f"[ipv4-addr:value = '{value}']"
    elif ioc_type == IOCType.DOMAIN:
        return f"[domain-name:value = '{value}']"
    elif ioc_type == IOCType.URL:
        return f"[url:value = '{value}']"
    elif ioc_type == IOCType.HASH_SHA256:
        return f"[file:hashes.'SHA-256' = '{value}']"
    elif ioc_type == IOCType.HASH_MD5:
        return f"[file:hashes.MD5 = '{value}']"
    return f"[mutex:name = '{value}']"


def compile_stix21_intelligence_bundle(indicators: list[Indicator]) -> dict:
    """
    Serializes a database record collection into a structured STIX 2.1
    JSON compliance bundle (FR-24 Framework Compliance).
    """
    bundle_id = f"bundle--{uuid.uuid4()}"
    stix_objects = []

    for ioc in indicators:
        stix_indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": ioc.created_at.replace(tzinfo=timezone.utc).isoformat(),
            "modified": ioc.updated_at.replace(tzinfo=timezone.utc).isoformat(),
            "name": f"Threat Vector: {ioc.value}",
            "description": f"ThreatLens analyzed indicator with normalized severity score: {ioc.severity_score}",
            "indicator_types": ["malicious-activity"],
            "pattern": convert_type_to_stix_pattern(ioc.type, ioc.value),
            "pattern_type": "stix",
            "valid_from": ioc.first_seen.replace(tzinfo=timezone.utc).isoformat(),
            "object_marking_refs": [convert_tlp_to_stix(ioc.tlp)],
            "confidence": int(ioc.confidence),
        }
        stix_objects.append(stix_indicator)

    return {"type": "bundle", "id": bundle_id, "objects": stix_objects}


def compile_flat_csv_intelligence_ledger(indicators: list[Indicator]) -> str:
    """Compiles intelligence records into standard tabular CSV string structures for SIEM ingestion."""
    output = io.StringIO()
    writer = csv.writer(output, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)

    # Write header maps
    writer.writerow(
        [
            "id",
            "value",
            "type",
            "severity_score",
            "confidence",
            "tlp",
            "status",
            "last_seen",
        ]
    )

    for ioc in indicators:
        writer.writerow(
            [
                str(ioc.id),
                ioc.value,
                ioc.type.value,
                ioc.severity_score,
                ioc.confidence,
                ioc.tlp.value,
                ioc.status.value,
                ioc.last_seen.isoformat(),
            ]
        )

    return output.getvalue()
