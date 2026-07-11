import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .analyzer import analyze_email
from .ioc_analyzer import analyze_ioc
from .threat_intel import enrich_ioc, extract_iocs

INVESTIGATION_TYPES = {
    "EMAIL": "email",
    "IOC": "ioc",
    "URL": "url",
    "DOMAIN": "domain",
    "IP": "ip",
    "EMAIL_ADDRESS": "email_address",
    "FILE_HASH": "file_hash",
    "SOC_ALERT": "soc_alert",
}

PIPELINE_STAGES = {
    "NEW": "New",
    "ANALYZING": "Analyzing",
    "ENRICHED": "Enriched",
    "REVIEWED": "Reviewed",
    "CLOSED": "Closed",
}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
_URL_RE = re.compile(r"https?://[^\s)\]>\"]+")
_DOMAIN_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.IGNORECASE)


def detect_investigation_type(input_text: str) -> str:
    """Infer the most appropriate investigation workflow for a submission."""
    cleaned = (input_text or "").strip()
    if not cleaned:
        return INVESTIGATION_TYPES["EMAIL"]

    try:
        parsed = json.loads(cleaned)
    except (TypeError, json.JSONDecodeError):
        parsed = None

    if isinstance(parsed, dict):
        alert_keys = {"alert_id", "rule_name", "description", "severity", "source", "entities", "incident_id"}
        if alert_keys.intersection(parsed.keys()):
            return INVESTIGATION_TYPES["SOC_ALERT"]

    if cleaned.lower().startswith(("http://", "https://")):
        return INVESTIGATION_TYPES["URL"]

    if _IP_RE.match(cleaned):
        return INVESTIGATION_TYPES["IP"]

    if _EMAIL_RE.match(cleaned):
        return INVESTIGATION_TYPES["EMAIL_ADDRESS"]

    if _HASH_RE.match(cleaned):
        return INVESTIGATION_TYPES["FILE_HASH"]

    if _URL_RE.search(cleaned):
        return INVESTIGATION_TYPES["URL"]

    if _DOMAIN_RE.search(cleaned):
        return INVESTIGATION_TYPES["DOMAIN"]

    if cleaned.startswith("{") and cleaned.endswith("}"):
        return INVESTIGATION_TYPES["SOC_ALERT"]

    if re.search(r"^(from|subject|to|cc|date):", cleaned, re.IGNORECASE | re.MULTILINE):
        return INVESTIGATION_TYPES["EMAIL"]

    if any(token in cleaned.lower() for token in ["password", "verify", "click here", "urgent", "login", "suspicious"]):
        return INVESTIGATION_TYPES["EMAIL"]

    return INVESTIGATION_TYPES["IOC"]


def _coerce_payload_text(input_text: str, investigation_type: str) -> str:
    if investigation_type == INVESTIGATION_TYPES["SOC_ALERT"]:
        try:
            parsed = json.loads(input_text)
        except (TypeError, json.JSONDecodeError):
            parsed = {}

        if isinstance(parsed, dict):
            pieces = [
                parsed.get("title") or parsed.get("name") or "",
                parsed.get("description") or parsed.get("summary") or "",
                parsed.get("message") or "",
                parsed.get("rule_name") or "",
                parsed.get("severity") or "",
            ]
            return "\n".join(piece for piece in pieces if piece).strip()

    return input_text


def _extract_evidence(input_text: str) -> Dict[str, List[str]]:
    iocs = extract_iocs(input_text)
    evidence: Dict[str, List[str]] = {
        "urls": [],
        "domains": [],
        "ips": [],
        "emails": [],
        "hashes": [],
    }

    for item in iocs:
        ioc_type = item.get("ioc_type", "")
        value = item.get("ioc_value", "")
        if not value:
            continue
        if ioc_type == "URL":
            evidence["urls"].append(value)
        elif ioc_type == "Domain":
            evidence["domains"].append(value)
        elif ioc_type == "IP Address":
            evidence["ips"].append(value)
        elif ioc_type == "Email Address":
            evidence["emails"].append(value)
        elif ioc_type == "File Hash":
            evidence["hashes"].append(value)

    return evidence


def _build_enrichment_results(input_text: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for item in extract_iocs(input_text):
        normalized = enrich_ioc(item["ioc_value"], item["ioc_type"])
        results.append(normalized)
    return results


def _build_timeline(investigation_type: str, evidence: Dict[str, List[str]], enrichment_results: List[Dict[str, Any]], score: int) -> List[Dict[str, Any]]:
    stage_messages = [
        {"stage": PIPELINE_STAGES["NEW"], "message": "Investigation created and routed to the unified analysis pipeline."},
        {"stage": PIPELINE_STAGES["ANALYZING"], "message": f"{investigation_type.title()} input detected and routed to the appropriate analyzer."},
    ]

    if evidence["urls"] or evidence["domains"] or evidence["ips"] or evidence["emails"] or evidence["hashes"]:
        stage_messages.append({"stage": PIPELINE_STAGES["ANALYZING"], "message": f"Extracted {sum(len(values) for values in evidence.values())} evidence items from the submission."})

    if enrichment_results:
        stage_messages.append({"stage": PIPELINE_STAGES["ENRICHED"], "message": f"Threat intelligence enrichment completed for {len(enrichment_results)} IOC(s)."})

    stage_messages.append({"stage": PIPELINE_STAGES["REVIEWED"], "message": f"Risk assessment completed with a score of {score}/100."})
    stage_messages.append({"stage": PIPELINE_STAGES["REVIEWED"], "message": "Investigation summary and evidence package generated for analysts."})

    return stage_messages


def _build_graph(investigation_type: str, evidence: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    base_graph = [
        {"source": "Input", "target": investigation_type.title()},
        {"source": investigation_type.title(), "target": "Evidence"},
        {"source": "Evidence", "target": "Threat Intelligence"},
        {"source": "Threat Intelligence", "target": "Investigation"},
    ]

    if evidence["ips"]:
        base_graph.append({"source": "Evidence", "target": "IP"})
    if evidence["domains"]:
        base_graph.append({"source": "Evidence", "target": "Domain"})
    if evidence["urls"]:
        base_graph.append({"source": "Evidence", "target": "URL"})
    if evidence["hashes"]:
        base_graph.append({"source": "Evidence", "target": "Hash"})

    return base_graph


def _build_summary(investigation_type: str, score: int, confidence: int, evidence: Dict[str, List[str]], enrichment_results: List[Dict[str, Any]], analyst_report: Optional[Dict[str, Any]] = None) -> str:
    executive_summary = ""
    if isinstance(analyst_report, dict):
        executive_summary = analyst_report.get("executive_summary") or analyst_report.get("summary") or ""

    if not executive_summary:
        executive_summary = f"{investigation_type.title()} investigation completed with a risk score of {score}/100 and confidence of {confidence}/100."

    action_items = [
        "Review the extracted evidence and verify the indicators against internal telemetry.",
        "Escalate the case if the risk score is high or the enrichment sources show suspicious reputation values.",
    ]

    ioc_intelligence = []
    for item in enrichment_results[:3]:
        ioc_intelligence.append(f"{item.get('ioc_type')} {item.get('ioc_value')} -> risk {item.get('risk_score', 0)}/100")

    summary_parts = [
        executive_summary,
        f"Threat assessment: risk score {score}/100, confidence {confidence}/100.",
        "IOC intelligence: " + (", ".join(ioc_intelligence) if ioc_intelligence else "No enrichment results were produced."),
        "Recommended actions: " + " ".join(action_items),
    ]

    if evidence["urls"]:
        summary_parts.append(f"Observed URLs: {', '.join(evidence['urls'][:5])}")
    if evidence["domains"]:
        summary_parts.append(f"Observed domains: {', '.join(evidence['domains'][:5])}")
    if evidence["ips"]:
        summary_parts.append(f"Observed IP addresses: {', '.join(evidence['ips'][:5])}")

    return "\n\n".join(summary_parts)


def process_investigation_input(input_text: str, *, source_type: Optional[str] = None) -> Dict[str, Any]:
    """Route a submission through the unified investigation pipeline and return a normalized result."""
    investigation_type = source_type or detect_investigation_type(input_text)
    payload_text = _coerce_payload_text(input_text, investigation_type)

    analysis_result: Dict[str, Any]
    if investigation_type == INVESTIGATION_TYPES["SOC_ALERT"]:
        analysis_result = analyze_email(payload_text)
    elif investigation_type in {INVESTIGATION_TYPES["EMAIL"], INVESTIGATION_TYPES["EMAIL_ADDRESS"]}:
        analysis_result = analyze_email(payload_text)
    else:
        analysis_result = analyze_ioc(payload_text)

    evidence = _extract_evidence(payload_text)
    enrichment_results = _build_enrichment_results(payload_text)

    if investigation_type in {INVESTIGATION_TYPES["EMAIL"], INVESTIGATION_TYPES["SOC_ALERT"]}:
        score = analysis_result.get("score", 0)
        confidence = analysis_result.get("confidence", 0)
    else:
        score = analysis_result.get("reputation_score", analysis_result.get("score", 0))
        confidence = analysis_result.get("confidence", analysis_result.get("reputation_score", analysis_result.get("score", 0)))

    report = analysis_result.get("analyst_report")
    summary = _build_summary(
        investigation_type=investigation_type,
        score=int(score),
        confidence=int(confidence),
        evidence=evidence,
        enrichment_results=enrichment_results,
        analyst_report=report if isinstance(report, dict) else None,
    )

    timeline = _build_timeline(investigation_type, evidence, enrichment_results, int(score))
    graph = _build_graph(investigation_type, evidence)

    return {
        "investigation_type": investigation_type,
        "pipeline_stage": PIPELINE_STAGES["ANALYZING"],
        "summary": summary,
        "timeline": timeline,
        "graph": graph,
        "evidence": [
            item for category in evidence.values() for item in category
        ],
        "tags": [investigation_type, "unified-pipeline"],
        "urls": analysis_result.get("urls") or [],
        "sender": analysis_result.get("sender") or "",
        "score": int(score),
        "confidence": int(confidence),
        "analyst_report": analysis_result.get("analyst_report") or {},
        "analysis_source": investigation_type,
        **analysis_result,
    }
