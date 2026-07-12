import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Tuple

from sqlalchemy.orm import Session

from .models_db import Investigation, InvestigationTimeline, ThreatIntelIndicator


_MITRE_VERSION = "1.0"
_PERSISTENCE_KEYWORDS = (
    "persistence",
    "autostart",
    "startup",
    "scheduled task",
    "run key",
    "registry run",
)
_CREDENTIAL_KEYWORDS = (
    "password",
    "credentials",
    "verify account",
    "confirm identity",
    "login",
    "sign in",
    "account number",
    "routing number",
    "ssn",
)


def _safe_json(value: Any, fallback: Any) -> Any:
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


def parse_cached_mitre(raw_mitre: Any) -> Dict[str, Any] | None:
    parsed = _safe_json(raw_mitre, None)
    if not isinstance(parsed, dict):
        return None
    if not isinstance(parsed.get("mappings"), list):
        return None
    parsed.setdefault("metadata", {})
    return parsed


def _extract_timeline(session: Session, investigation_id: int) -> List[Dict[str, Any]]:
    rows = (
        session.query(InvestigationTimeline)
        .filter(InvestigationTimeline.investigation_id == investigation_id)
        .order_by(InvestigationTimeline.created_at.asc(), InvestigationTimeline.id.asc())
        .all()
    )
    timeline = []
    for row in rows:
        timeline.append(
            {
                "event_type": row.event_type,
                "title": row.title,
                "description": row.description,
                "source": row.source,
                "metadata": _safe_json(row.metadata_json, {}),
                "timestamp": row.created_at.isoformat() if row.created_at else None,
            }
        )
    return timeline


def _extract_graph_signature(investigation: Investigation) -> str:
    graph = _safe_json(investigation.graph, {})
    if isinstance(graph, dict):
        metadata = graph.get("metadata") or {}
        if isinstance(metadata, dict) and metadata.get("source_signature"):
            return str(metadata["source_signature"])
    return ""


def compute_mitre_source_signature(
    investigation: Investigation,
    indicators: Iterable[ThreatIntelIndicator],
    timeline: List[Dict[str, Any]],
) -> str:
    indicator_payload = []
    for ind in indicators:
        indicator_payload.append(
            {
                "ioc_value": ind.ioc_value,
                "ioc_type": ind.ioc_type,
                "risk_score": ind.risk_score,
                "reputation": ind.reputation,
                "confidence": ind.confidence,
                "detection_summary": ind.detection_summary,
                "provider_responses": _safe_json(ind.provider_responses, {}),
            }
        )

    payload = {
        "case_id": investigation.case_id,
        "status": investigation.status,
        "threat_level": investigation.threat_level,
        "risk_score": investigation.phishing_score,
        "confidence": investigation.confidence,
        "summary": investigation.summary,
        "submitted_text": investigation.submitted_text,
        "analyst_notes": investigation.analyst_notes,
        "analyst_report": _safe_json(investigation.analyst_report, investigation.analyst_report or ""),
        "evidence": _safe_json(investigation.evidence, []),
        "urls": _safe_json(investigation.urls, []),
        "graph_signature": _extract_graph_signature(investigation),
        "timeline": timeline,
        "indicators": sorted(indicator_payload, key=lambda row: (row["ioc_type"], row["ioc_value"])),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _analyze_signals(
    investigation: Investigation,
    indicators: List[ThreatIntelIndicator],
    timeline: List[Dict[str, Any]],
) -> Dict[str, Any]:
    report = _safe_json(investigation.analyst_report, {})
    key_indicators = report.get("key_indicators", []) if isinstance(report, dict) else []
    heuristic_rules = report.get("heuristic_rules", []) if isinstance(report, dict) else []

    text_parts = [
        investigation.submitted_text or "",
        investigation.summary or "",
        investigation.analyst_notes or "",
        json.dumps(report) if isinstance(report, dict) else str(report or ""),
    ]
    text_blob = "\n".join(text_parts).lower()

    urls = _safe_json(investigation.urls, [])
    evidence_items = _safe_json(investigation.evidence, [])
    event_types = {str(item.get("event_type") or "") for item in timeline}

    vt_hits = []
    for ind in indicators:
        providers = _safe_json(ind.provider_responses, {})
        vt = providers.get("VirusTotal") if isinstance(providers, dict) else None
        if not isinstance(vt, dict):
            continue
        data = vt.get("data") if isinstance(vt.get("data"), dict) else {}
        malicious = int(data.get("malicious") or 0)
        suspicious = int(data.get("suspicious") or 0)
        if malicious > 0 or suspicious > 0:
            vt_hits.append(
                {
                    "ioc_type": ind.ioc_type,
                    "ioc_value": ind.ioc_value,
                    "malicious": malicious,
                    "suspicious": suspicious,
                }
            )

    domain_indicators = [ind for ind in indicators if ind.ioc_type == "Domain"]
    url_indicators = [ind for ind in indicators if ind.ioc_type == "URL"]
    ip_indicators = [ind for ind in indicators if ind.ioc_type == "IP Address"]
    hash_indicators = [ind for ind in indicators if ind.ioc_type == "File Hash"]

    return {
        "report": report,
        "key_indicators": key_indicators if isinstance(key_indicators, list) else [],
        "heuristic_rules": heuristic_rules if isinstance(heuristic_rules, list) else [],
        "text_blob": text_blob,
        "urls": urls if isinstance(urls, list) else [],
        "evidence_items": evidence_items if isinstance(evidence_items, list) else [],
        "event_types": event_types,
        "vt_hits": vt_hits,
        "domain_indicators": domain_indicators,
        "url_indicators": url_indicators,
        "ip_indicators": ip_indicators,
        "hash_indicators": hash_indicators,
    }


def _mapping(
    attack_id: str,
    technique: str,
    tactic: str,
    confidence: int,
    evidence: List[str],
    explanation: str,
) -> Dict[str, Any]:
    return {
        "attack_id": attack_id,
        "technique": technique,
        "tactic": tactic,
        "confidence": max(0, min(100, int(confidence))),
        "evidence": evidence,
        "explanation": explanation,
    }


def build_mitre_mappings(
    investigation: Investigation,
    indicators: List[ThreatIntelIndicator],
    timeline: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    signals = _analyze_signals(investigation, indicators, timeline)
    mappings: List[Dict[str, Any]] = []

    has_credential_indicator = any(
        isinstance(item, dict) and str(item.get("indicator", "")).lower() == "credential_harvest"
        for item in signals["key_indicators"]
    )
    credential_terms = [term for term in _CREDENTIAL_KEYWORDS if term in signals["text_blob"]]

    if signals["url_indicators"] or signals["urls"]:
        evidence = [
            f"URL IOC count: {len(signals['url_indicators']) or len(signals['urls'])}",
            f"Timeline has phishing analysis event: {'phishing_analysis_completed' in signals['event_types']}",
        ]
        if signals["vt_hits"]:
            evidence.append(f"VirusTotal flagged URL/related IOC entries: {len(signals['vt_hits'])}")
        confidence = 60 + (10 if signals["vt_hits"] else 0) + (10 if investigation.phishing_score >= 60 else 0)
        mappings.append(
            _mapping(
                "T1566.002",
                "Phishing: Spearphishing Link",
                "Initial Access",
                confidence,
                evidence,
                "Investigation contains link-based phishing indicators and URL-focused evidence consistent with spearphishing via link delivery.",
            )
        )

    if has_credential_indicator or credential_terms:
        evidence = []
        if has_credential_indicator:
            evidence.append("Analyst report includes credential_harvest indicator.")
        if credential_terms:
            evidence.append("Credential-related terms found: " + ", ".join(sorted(set(credential_terms))[:6]))
        if signals["url_indicators"]:
            evidence.append("Credential prompt appears alongside URL indicators.")
        confidence = 62 + (12 if has_credential_indicator else 0) + (8 if signals["url_indicators"] else 0)
        mappings.append(
            _mapping(
                "T1056.003",
                "Input Capture: Web Portal Capture",
                "Credential Access",
                confidence,
                evidence,
                "Case evidence indicates credential collection behavior through phishing-style prompts and/or portal-oriented lures.",
            )
        )

    suspicious_domain_rules = [
        item
        for item in signals["heuristic_rules"]
        if isinstance(item, dict)
        and str(item.get("rule", "")) in {"typosquatting", "brand_impersonation", "disposable_provider"}
    ]
    if signals["domain_indicators"] and suspicious_domain_rules:
        evidence = [
            f"Domain IOC count: {len(signals['domain_indicators'])}",
            f"Suspicious domain heuristic rules: {len(suspicious_domain_rules)}",
        ]
        mappings.append(
            _mapping(
                "T1583.001",
                "Acquire Infrastructure: Domains",
                "Resource Development",
                66,
                evidence,
                "Suspicious domain behavior and heuristic domain impersonation signals align with malicious domain infrastructure usage.",
            )
        )

    if signals["vt_hits"] and (signals["ip_indicators"] or signals["domain_indicators"] or signals["url_indicators"]):
        evidence = [
            f"VirusTotal suspicious/malicious hit count: {len(signals['vt_hits'])}",
            f"Network IOC counts - URL:{len(signals['url_indicators'])}, Domain:{len(signals['domain_indicators'])}, IP:{len(signals['ip_indicators'])}",
        ]
        mappings.append(
            _mapping(
                "T1071.001",
                "Application Layer Protocol: Web Protocols",
                "Command and Control",
                64,
                evidence,
                "Network-facing IOCs with malicious external reputation suggest potential C2-style web communication behavior.",
            )
        )

    dangerous_file_heuristics = [
        item
        for item in signals["heuristic_rules"]
        if isinstance(item, dict) and str(item.get("rule", "")) == "dangerous_extension"
    ]
    if signals["hash_indicators"] or dangerous_file_heuristics:
        evidence = []
        if signals["hash_indicators"]:
            evidence.append(f"File hash IOC count: {len(signals['hash_indicators'])}")
        if dangerous_file_heuristics:
            evidence.append(f"Dangerous file heuristic findings: {len(dangerous_file_heuristics)}")
        mappings.append(
            _mapping(
                "T1204.002",
                "User Execution: Malicious File",
                "Execution",
                61,
                evidence,
                "File-oriented indicators and/or dangerous attachment heuristics suggest malware delivery through user-executed content.",
            )
        )

    if has_credential_indicator and not signals["url_indicators"]:
        evidence = [
            "Credential harvesting indicators present without direct execution evidence.",
            f"Timeline event count: {len(timeline)}",
        ]
        mappings.append(
            _mapping(
                "T1598",
                "Phishing for Information",
                "Reconnaissance",
                58,
                evidence,
                "Credential solicitation behavior can overlap reconnaissance-oriented phishing for information collection.",
            )
        )

    persistence_terms = [term for term in _PERSISTENCE_KEYWORDS if term in signals["text_blob"]]
    if persistence_terms:
        evidence = ["Persistence-related keywords found: " + ", ".join(sorted(set(persistence_terms)))]
        mappings.append(
            _mapping(
                "T1547",
                "Boot or Logon Autostart Execution",
                "Persistence",
                55,
                evidence,
                "Analyst or investigation text references persistence-oriented behavior consistent with autostart persistence mechanisms.",
            )
        )

    # De-duplicate by ATT&CK ID while keeping highest confidence entry.
    dedup: Dict[str, Dict[str, Any]] = {}
    for mapping in mappings:
        attack_id = mapping["attack_id"]
        current = dedup.get(attack_id)
        if current is None or mapping["confidence"] > current["confidence"]:
            dedup[attack_id] = mapping

    return sorted(dedup.values(), key=lambda item: (-item["confidence"], item["attack_id"]))


def mitre_needs_refresh(cached: Dict[str, Any] | None, source_signature: str) -> bool:
    if not cached:
        return True
    metadata = cached.get("metadata")
    if not isinstance(metadata, dict):
        return True
    return metadata.get("source_signature") != source_signature


def refresh_investigation_mitre(session: Session, investigation: Investigation, *, force: bool = False) -> Dict[str, Any]:
    indicators = (
        session.query(ThreatIntelIndicator)
        .filter(ThreatIntelIndicator.investigation_id == investigation.id)
        .order_by(ThreatIntelIndicator.risk_score.desc(), ThreatIntelIndicator.created_at.desc())
        .all()
    )
    timeline = _extract_timeline(session, investigation.id)
    source_signature = compute_mitre_source_signature(investigation, indicators, timeline)
    cached = parse_cached_mitre(investigation.mitre_mappings)

    if not force and not mitre_needs_refresh(cached, source_signature):
        return cached or {"mappings": [], "metadata": {"source_signature": source_signature}}

    mappings = build_mitre_mappings(investigation, indicators, timeline)
    payload = {
        "mappings": mappings,
        "metadata": {
            "mitre_version": _MITRE_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source_signature": source_signature,
            "case_id": investigation.case_id,
        },
    }
    investigation.mitre_mappings = json.dumps(payload)
    return payload
