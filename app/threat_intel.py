import ipaddress
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from .models_db import Investigation, ThreatIntelIndicator
from .threat_intel_providers import (
    AbuseIPDBProvider,
    AlienVaultOTXProvider,
    BaseThreatIntelProvider,
    DnsProvider,
    VirusTotalProvider,
    WhoisProvider,
)

IOC_TYPES = {
    "IP_ADDRESS": "IP Address",
    "DOMAIN": "Domain",
    "URL": "URL",
    "EMAIL_ADDRESS": "Email Address",
    "FILE_HASH": "File Hash",
}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
_URL_RE = re.compile(r"https?://[^\s)\]>\"]+")
_DOMAIN_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.IGNORECASE)


def _normalize_value(ioc_type: str, value: str) -> str:
    cleaned = value.strip().rstrip(".,;:)")
    if ioc_type == IOC_TYPES["DOMAIN"]:
        return cleaned.lower()
    if ioc_type == IOC_TYPES["EMAIL_ADDRESS"]:
        return cleaned.lower()
    if ioc_type == IOC_TYPES["FILE_HASH"]:
        return cleaned.lower()
    if ioc_type == IOC_TYPES["IP_ADDRESS"]:
        try:
            return str(ipaddress.ip_address(cleaned))
        except ValueError:
            return cleaned
    return cleaned


def detect_ioc_type(value: str) -> str:
    cleaned = (value or "").strip()
    if not cleaned:
        return IOC_TYPES["DOMAIN"]

    if _IP_RE.match(cleaned):
        try:
            ipaddress.ip_address(cleaned)
            return IOC_TYPES["IP_ADDRESS"]
        except ValueError:
            pass

    if _EMAIL_RE.match(cleaned):
        return IOC_TYPES["EMAIL_ADDRESS"]

    if cleaned.lower().startswith(("http://", "https://")):
        return IOC_TYPES["URL"]

    if cleaned.lower().startswith(("md5:", "sha1:", "sha256:")) or _HASH_RE.match(cleaned):
        return IOC_TYPES["FILE_HASH"]

    if "." in cleaned and "/" not in cleaned:
        return IOC_TYPES["DOMAIN"]

    return IOC_TYPES["DOMAIN"]


def extract_iocs(text: str) -> List[Dict[str, Any]]:
    """Extract and normalize IOCs from a free-form text body."""
    discovered: Dict[tuple[str, str], Dict[str, Any]] = {}

    for match in _URL_RE.findall(text or ""):
        value = match.rstrip(".,;:)")
        ioc_type = IOC_TYPES["URL"]
        normalized = _normalize_value(ioc_type, value)
        key = (ioc_type, normalized)
        discovered[key] = {"ioc_value": normalized, "ioc_type": ioc_type}

    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or ""):
        ioc_type = IOC_TYPES["IP_ADDRESS"]
        normalized = _normalize_value(ioc_type, match)
        key = (ioc_type, normalized)
        discovered[key] = {"ioc_value": normalized, "ioc_type": ioc_type}

    for match in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text or ""):
        ioc_type = IOC_TYPES["EMAIL_ADDRESS"]
        normalized = _normalize_value(ioc_type, match)
        key = (ioc_type, normalized)
        discovered[key] = {"ioc_value": normalized, "ioc_type": ioc_type}

    for match in re.findall(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b", text or ""):
        ioc_type = IOC_TYPES["FILE_HASH"]
        normalized = _normalize_value(ioc_type, match)
        key = (ioc_type, normalized)
        discovered[key] = {"ioc_value": normalized, "ioc_type": ioc_type}

    for match in _DOMAIN_RE.findall(text or ""):
        value = match.rstrip(".,;:)")
        if value.lower().startswith(("http://", "https://")):
            continue
        if "@" in value:
            continue
        ioc_type = IOC_TYPES["DOMAIN"]
        normalized = _normalize_value(ioc_type, value)
        key = (ioc_type, normalized)
        discovered[key] = {"ioc_value": normalized, "ioc_type": ioc_type}

    return list(discovered.values())


def _get_provider_instances() -> List[BaseThreatIntelProvider]:
    return [
        VirusTotalProvider(),
        AbuseIPDBProvider(),
        AlienVaultOTXProvider(),
        WhoisProvider(),
        DnsProvider(),
    ]


def normalize_ioc_entry(ioc_value: str, ioc_type: str, provider_results: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Normalize an extracted IOC into the shared schema used by the UI and database."""
    provider_results = provider_results or {}
    source_providers = [name for name, result in provider_results.items() if result.get("status") not in {"not_applicable", "not_configured"}]

    reputation = 50
    if ioc_type == IOC_TYPES["IP_ADDRESS"]:
        reputation += 20
    elif ioc_type == IOC_TYPES["DOMAIN"]:
        reputation += 10
    elif ioc_type == IOC_TYPES["URL"]:
        reputation += 15
    elif ioc_type == IOC_TYPES["EMAIL_ADDRESS"]:
        reputation += 5

    if any(result.get("status") == "unavailable" for result in provider_results.values() if isinstance(result, dict)):
        reputation += 10
    if any(result.get("status") == "simulated" for result in provider_results.values() if isinstance(result, dict)):
        reputation += 5

    confidence = min(100, max(30, reputation - 10))
    risk_score = min(100, max(0, reputation))
    evidence = [result.get("details") for result in provider_results.values() if isinstance(result, dict) and result.get("details")]

    summary = (
        f"{ioc_type} {ioc_value} received enrichment from {', '.join(source_providers) or 'no providers'}."
        if source_providers
        else f"No enrichment providers produced results for {ioc_value}."
    )

    return {
        "ioc_value": ioc_value,
        "ioc_type": ioc_type,
        "source_providers": source_providers,
        "reputation": max(0, min(100, reputation)),
        "confidence": confidence,
        "risk_score": risk_score,
        "detection_summary": summary,
        "supporting_evidence": evidence,
        "provider_results": provider_results,
    }


def generate_ai_summary(ioc_entry: Dict[str, Any]) -> str:
    if ioc_entry["risk_score"] >= 80:
        risk_phrase = "high-risk"
    elif ioc_entry["risk_score"] >= 60:
        risk_phrase = "moderate-risk"
    else:
        risk_phrase = "low-risk"
    return (
        f"The {ioc_entry['ioc_type'].lower()} {ioc_entry['ioc_value']} appears {risk_phrase}. "
        f"Enrichment sources reviewed: {', '.join(ioc_entry['source_providers']) or 'none'}."
    )


def enrich_ioc(ioc_value: str, ioc_type: str) -> Dict[str, Any]:
    """Run all providers for an IOC and merge the results into one normalized payload."""
    # Use the centralized ThreatIntelEngine to orchestrate provider enrichment.
    try:
        from .threatintel.engine import ThreatIntelEngine

        engine = ThreatIntelEngine()
        provider_results = engine.enrich(ioc_value, ioc_type)
    except Exception as exc:
        # Fail-safe: fall back to legacy provider loop if engine fails for any reason
        provider_results = {}
        for provider in _get_provider_instances():
            if not provider.supports(ioc_type):
                continue
            try:
                result = provider.enrich(ioc_value, ioc_type)
            except Exception as exc2:  # provider failures must never break the pipeline
                result = {"status": "error", "details": str(exc2)}
            provider_results[provider.name] = result

    normalized = normalize_ioc_entry(ioc_value, ioc_type, provider_results)
    normalized["summary"] = generate_ai_summary(normalized)
    return normalized


def process_investigation_enrichment(investigation_id: int) -> List[Dict[str, Any]]:
    """Extract IOCs from an investigation and store the enrichment results in the database."""
    from . import database as database_module

    with database_module.SessionLocal() as session:
        investigation = session.get(Investigation, investigation_id)
        if not investigation:
            return []

        payload_text = "\n".join(
            part for part in [investigation.submitted_text, investigation.analyst_notes, investigation.analyst_report] if part
        )
        iocs = extract_iocs(payload_text)
        if not iocs:
            return []

        for item in iocs:
            normalized = enrich_ioc(item["ioc_value"], item["ioc_type"])
            existing = (
                session.query(ThreatIntelIndicator)
                .filter(ThreatIntelIndicator.investigation_id == investigation.id)
                .filter(ThreatIntelIndicator.ioc_value == normalized["ioc_value"])
                .filter(ThreatIntelIndicator.ioc_type == normalized["ioc_type"])
                .first()
            )
            if existing:
                continue

            indicator = ThreatIntelIndicator(
                investigation_id=investigation.id,
                ioc_value=normalized["ioc_value"],
                ioc_type=normalized["ioc_type"],
                source_providers=json.dumps(normalized["source_providers"]),
                reputation=normalized["reputation"],
                confidence=normalized["confidence"],
                risk_score=normalized["risk_score"],
                detection_summary=normalized["detection_summary"],
                evidence=json.dumps(normalized["supporting_evidence"]),
                provider_responses=json.dumps(normalized["provider_results"]),
            )
            session.add(indicator)

        if not investigation.summary:
            top_indicator = max(
                [
                    indicator
                    for indicator in session.query(ThreatIntelIndicator)
                    .filter(ThreatIntelIndicator.investigation_id == investigation.id)
                    .all()
                ],
                key=lambda row: row.risk_score,
                default=None,
            )
            if top_indicator:
                investigation.summary = top_indicator.detection_summary

        session.commit()
        return [
            {
                "ioc_value": item["ioc_value"],
                "ioc_type": item["ioc_type"],
                "summary": enrich_ioc(item["ioc_value"], item["ioc_type"])["summary"],
            }
            for item in iocs
        ]
