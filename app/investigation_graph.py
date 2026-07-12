import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from .models_db import Investigation, ThreatIntelIndicator
from .threat_intel import extract_iocs

_GRAPH_VERSION = "1.0"
_EMAIL_EXTRACT_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _safe_json_loads(value: Any, fallback: Any) -> Any:
    if value is None:
        return fallback
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return fallback
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return fallback
    return fallback


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value)
    except TypeError:
        return str(value)


def _extract_recipients(submitted_text: str) -> List[str]:
    recipients: List[str] = []
    for line in (submitted_text or "").splitlines():
        lowered = line.lower().strip()
        if lowered.startswith("to:") or lowered.startswith("cc:"):
            recipients.extend(_EMAIL_EXTRACT_RE.findall(line))
    # Deduplicate while preserving order.
    seen = set()
    unique = []
    for recipient in recipients:
        normalized = recipient.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append(normalized)
    return unique


def _domain_from_url(value: str) -> str:
    parsed = urlparse(value)
    return (parsed.hostname or "").lower()


def _domain_from_email(value: str) -> str:
    if "@" not in value:
        return ""
    return value.split("@", 1)[1].lower().strip()


def _normalize_ioc_type(raw_type: str, value: str) -> str:
    cleaned = (raw_type or "").strip().lower()
    if cleaned in {"url"}:
        return "URL"
    if cleaned in {"domain"}:
        return "Domain"
    if cleaned in {"ip address", "ip", "ip_address"}:
        return "IP Address"
    if cleaned in {"email address", "email", "email_address"}:
        return "Email Address"
    if cleaned in {"file hash", "hash", "file_hash"}:
        return "File Hash"

    probe = (value or "").strip().lower()
    if probe.startswith("http://") or probe.startswith("https://"):
        return "URL"
    if "@" in probe and "." in probe.split("@")[-1]:
        return "Email Address"
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", probe):
        return "IP Address"
    if re.match(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", probe):
        return "File Hash"
    return "Domain"


def _ioc_node_id(ioc_type: str, value: str) -> str:
    return f"ioc:{ioc_type.lower().replace(' ', '_')}:{value.lower()}"


def _node_type_for_ioc(ioc_type: str) -> str:
    mapping = {
        "URL": "URL",
        "Domain": "Domain",
        "IP Address": "IP Address",
        "Email Address": "Email Address",
        "File Hash": "File Hash",
    }
    return mapping.get(ioc_type, "Domain")


def _upsert_node(nodes: Dict[str, Dict[str, Any]], *, node_id: str, node_type: str, label: str, metadata: Dict[str, Any]) -> None:
    if node_id in nodes:
        existing = nodes[node_id]
        existing_meta = existing.setdefault("metadata", {})
        for key, value in metadata.items():
            if key not in existing_meta:
                existing_meta[key] = value
        return

    nodes[node_id] = {
        "id": node_id,
        "type": node_type,
        "label": label,
        "metadata": metadata,
    }


def _add_edge(edges: Dict[Tuple[str, str, str], Dict[str, Any]], *, source: str, target: str, relationship: str, metadata: Dict[str, Any]) -> None:
    key = (source, target, relationship)
    if key in edges:
        existing = edges[key].setdefault("metadata", {})
        for k, v in metadata.items():
            if k not in existing:
                existing[k] = v
        return

    edges[key] = {
        "source": source,
        "target": target,
        "relationship": relationship,
        "metadata": metadata,
    }


def _collect_iocs(investigation: Investigation, indicators: Iterable[ThreatIntelIndicator]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    ioc_map: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for indicator in indicators:
        ioc_type = _normalize_ioc_type(indicator.ioc_type, indicator.ioc_value)
        value = (indicator.ioc_value or "").strip()
        if not value:
            continue
        key = (ioc_type, value.lower())
        ioc_map[key] = {
            "ioc_type": ioc_type,
            "ioc_value": value,
            "provider_responses": _safe_json_loads(indicator.provider_responses, {}),
        }

    searchable_text = "\n".join(
        part
        for part in [
            _as_text(investigation.submitted_text),
            _as_text(investigation.analyst_notes),
            _as_text(investigation.analyst_report),
        ]
        if part
    )
    for extracted in extract_iocs(searchable_text):
        ioc_type = _normalize_ioc_type(extracted.get("ioc_type", ""), extracted.get("ioc_value", ""))
        value = (extracted.get("ioc_value") or "").strip()
        if not value:
            continue
        key = (ioc_type, value.lower())
        ioc_map.setdefault(
            key,
            {
                "ioc_type": ioc_type,
                "ioc_value": value,
                "provider_responses": {},
            },
        )

    for value in _safe_json_loads(investigation.urls, []):
        candidate = str(value).strip()
        if not candidate:
            continue
        ioc_map.setdefault(
            ("URL", candidate.lower()),
            {"ioc_type": "URL", "ioc_value": candidate, "provider_responses": {}},
        )

    for value in _safe_json_loads(investigation.evidence, []):
        candidate = str(value).strip()
        if not candidate:
            continue
        inferred = _normalize_ioc_type("", candidate)
        ioc_map.setdefault(
            (inferred, candidate.lower()),
            {"ioc_type": inferred, "ioc_value": candidate, "provider_responses": {}},
        )

    return ioc_map


def compute_graph_source_signature(investigation: Investigation, indicators: Iterable[ThreatIntelIndicator]) -> str:
    ioc_payload = []
    for entry in _collect_iocs(investigation, indicators).values():
        ioc_payload.append(
            {
                "ioc_type": entry["ioc_type"],
                "ioc_value": entry["ioc_value"],
                "providers": sorted((entry.get("provider_responses") or {}).keys()),
            }
        )

    indicator_payload = []
    for indicator in indicators:
        indicator_payload.append(
            {
                "ioc_type": indicator.ioc_type,
                "ioc_value": indicator.ioc_value,
                "provider_responses": _safe_json_loads(indicator.provider_responses, {}),
                "risk_score": indicator.risk_score,
                "reputation": indicator.reputation,
                "confidence": indicator.confidence,
            }
        )

    payload = {
        "case_id": investigation.case_id,
        "sender": investigation.sender or "",
        "submitted_text": investigation.submitted_text or "",
        "urls": _safe_json_loads(investigation.urls, []),
        "evidence": _safe_json_loads(investigation.evidence, []),
        "analyst_notes": investigation.analyst_notes or "",
        "analyst_report": _safe_json_loads(investigation.analyst_report, investigation.analyst_report or ""),
        "iocs": sorted(ioc_payload, key=lambda row: (row["ioc_type"], row["ioc_value"])),
        "indicators": sorted(indicator_payload, key=lambda row: (row["ioc_type"], row["ioc_value"])),
    }

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_cached_graph(raw_graph: Any) -> Dict[str, Any] | None:
    parsed = _safe_json_loads(raw_graph, None)
    if not isinstance(parsed, dict):
        return None
    if not isinstance(parsed.get("nodes"), list) or not isinstance(parsed.get("edges"), list):
        return None
    parsed.setdefault("metadata", {})
    return parsed


def graph_needs_refresh(cached_graph: Dict[str, Any] | None, source_signature: str) -> bool:
    if not cached_graph:
        return True
    metadata = cached_graph.get("metadata")
    if not isinstance(metadata, dict):
        return True
    return metadata.get("source_signature") != source_signature


def build_relationship_graph(investigation: Investigation, indicators: Iterable[ThreatIntelIndicator]) -> Dict[str, Any]:
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    investigation_node_id = f"investigation:{investigation.case_id}"
    _upsert_node(
        nodes,
        node_id=investigation_node_id,
        node_type="Investigation",
        label=investigation.case_id,
        metadata={
            "title": investigation.title,
            "status": investigation.status,
            "threat_level": investigation.threat_level,
            "investigation_type": investigation.investigation_type,
        },
    )

    sender_email = (investigation.sender or "").strip().lower()
    if sender_email:
        sender_role_node = f"sender:{sender_email}"
        sender_email_node = f"email:{sender_email}"
        _upsert_node(
            nodes,
            node_id=sender_role_node,
            node_type="Sender",
            label=sender_email,
            metadata={"address": sender_email},
        )
        _upsert_node(
            nodes,
            node_id=sender_email_node,
            node_type="Email Address",
            label=sender_email,
            metadata={"address": sender_email, "role": "sender"},
        )
        _add_edge(
            edges,
            source=investigation_node_id,
            target=sender_role_node,
            relationship="has_sender",
            metadata={},
        )
        _add_edge(
            edges,
            source=sender_role_node,
            target=sender_email_node,
            relationship="uses_address",
            metadata={},
        )

        sender_domain = _domain_from_email(sender_email)
        if sender_domain:
            sender_domain_node = f"domain:{sender_domain}"
            _upsert_node(
                nodes,
                node_id=sender_domain_node,
                node_type="Domain",
                label=sender_domain,
                metadata={"derived_from": "sender"},
            )
            _add_edge(
                edges,
                source=sender_email_node,
                target=sender_domain_node,
                relationship="belongs_to_domain",
                metadata={"derived": True},
            )

    recipients = _extract_recipients(investigation.submitted_text or "")
    for recipient in recipients:
        recipient_role_node = f"recipient:{recipient}"
        recipient_email_node = f"email:{recipient}"
        _upsert_node(
            nodes,
            node_id=recipient_role_node,
            node_type="Recipient",
            label=recipient,
            metadata={"address": recipient},
        )
        _upsert_node(
            nodes,
            node_id=recipient_email_node,
            node_type="Email Address",
            label=recipient,
            metadata={"address": recipient, "role": "recipient"},
        )
        _add_edge(
            edges,
            source=investigation_node_id,
            target=recipient_role_node,
            relationship="has_recipient",
            metadata={},
        )
        _add_edge(
            edges,
            source=recipient_role_node,
            target=recipient_email_node,
            relationship="uses_address",
            metadata={},
        )

        recipient_domain = _domain_from_email(recipient)
        if recipient_domain:
            recipient_domain_node = f"domain:{recipient_domain}"
            _upsert_node(
                nodes,
                node_id=recipient_domain_node,
                node_type="Domain",
                label=recipient_domain,
                metadata={"derived_from": "recipient"},
            )
            _add_edge(
                edges,
                source=recipient_email_node,
                target=recipient_domain_node,
                relationship="belongs_to_domain",
                metadata={"derived": True},
            )

    ioc_map = _collect_iocs(investigation, indicators)
    for entry in ioc_map.values():
        ioc_type = entry["ioc_type"]
        ioc_value = entry["ioc_value"]
        ioc_node = _ioc_node_id(ioc_type, ioc_value)
        _upsert_node(
            nodes,
            node_id=ioc_node,
            node_type=_node_type_for_ioc(ioc_type),
            label=ioc_value,
            metadata={"ioc_type": ioc_type},
        )
        _add_edge(
            edges,
            source=investigation_node_id,
            target=ioc_node,
            relationship="contains_indicator",
            metadata={"ioc_type": ioc_type},
        )

        if ioc_type == "URL":
            domain = _domain_from_url(ioc_value)
            if domain:
                domain_node = f"domain:{domain}"
                _upsert_node(
                    nodes,
                    node_id=domain_node,
                    node_type="Domain",
                    label=domain,
                    metadata={"derived_from": "url"},
                )
                _add_edge(
                    edges,
                    source=ioc_node,
                    target=domain_node,
                    relationship="resolves_to_domain",
                    metadata={"derived": True},
                )

        if ioc_type == "Email Address":
            domain = _domain_from_email(ioc_value)
            if domain:
                domain_node = f"domain:{domain}"
                _upsert_node(
                    nodes,
                    node_id=domain_node,
                    node_type="Domain",
                    label=domain,
                    metadata={"derived_from": "email"},
                )
                _add_edge(
                    edges,
                    source=ioc_node,
                    target=domain_node,
                    relationship="belongs_to_domain",
                    metadata={"derived": True},
                )

        provider_responses = entry.get("provider_responses") or {}
        for provider_name, provider_payload in provider_responses.items():
            provider_node = f"provider:{provider_name.lower().replace(' ', '_')}"
            _upsert_node(
                nodes,
                node_id=provider_node,
                node_type="Threat Intelligence Provider",
                label=provider_name,
                metadata={},
            )
            _add_edge(
                edges,
                source=ioc_node,
                target=provider_node,
                relationship="enriched_by_provider",
                metadata={"status": provider_payload.get("status") if isinstance(provider_payload, dict) else None},
            )

            if provider_name.lower() == "virustotal":
                vt_node = f"vt_result:{ioc_type.lower().replace(' ', '_')}:{ioc_value.lower()}"
                vt_payload = provider_payload if isinstance(provider_payload, dict) else {}
                _upsert_node(
                    nodes,
                    node_id=vt_node,
                    node_type="VirusTotal Result",
                    label=f"VT {ioc_value}",
                    metadata={
                        "status": vt_payload.get("status"),
                        "data": vt_payload.get("data", {}),
                    },
                )
                _add_edge(
                    edges,
                    source=ioc_node,
                    target=vt_node,
                    relationship="enriched_by_virustotal",
                    metadata={"status": vt_payload.get("status")},
                )
                _add_edge(
                    edges,
                    source=vt_node,
                    target=provider_node,
                    relationship="provided_by",
                    metadata={},
                )

            if provider_name.lower() == "dns" and isinstance(provider_payload, dict):
                records = provider_payload.get("records") or {}
                for ip in records.get("A", []) if isinstance(records.get("A"), list) else []:
                    ip_value = str(ip).strip()
                    if not ip_value:
                        continue
                    ip_node = f"ip:{ip_value}"
                    _upsert_node(
                        nodes,
                        node_id=ip_node,
                        node_type="IP Address",
                        label=ip_value,
                        metadata={"derived_from": "dns"},
                    )
                    _add_edge(
                        edges,
                        source=ioc_node,
                        target=ip_node,
                        relationship="resolves_to_ip",
                        metadata={"source_provider": "DNS"},
                    )

    signature = compute_graph_source_signature(investigation, indicators)
    graph = {
        "nodes": sorted(nodes.values(), key=lambda n: (n["type"], n["id"])),
        "edges": sorted(edges.values(), key=lambda e: (e["relationship"], e["source"], e["target"])),
        "metadata": {
            "graph_version": _GRAPH_VERSION,
            "generated_at": "",
            "source_signature": signature,
            "case_id": investigation.case_id,
        },
    }
    return graph


def refresh_investigation_graph(session: Session, investigation: Investigation, *, force: bool = False) -> Dict[str, Any]:
    indicators = (
        session.query(ThreatIntelIndicator)
        .filter(ThreatIntelIndicator.investigation_id == investigation.id)
        .order_by(ThreatIntelIndicator.created_at.desc(), ThreatIntelIndicator.id.desc())
        .all()
    )

    signature = compute_graph_source_signature(investigation, indicators)
    cached_graph = parse_cached_graph(investigation.graph)

    if not force and not graph_needs_refresh(cached_graph, signature):
        return cached_graph or {"nodes": [], "edges": [], "metadata": {"source_signature": signature}}

    graph = build_relationship_graph(investigation, indicators)
    graph["metadata"]["generated_at"] = datetime.now(timezone.utc).isoformat()
    investigation.graph = json.dumps(graph)
    return graph
