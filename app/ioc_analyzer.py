import ipaddress
import json
import os
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .utils import get_dns_records, get_whois_creation_date, is_suspicious_tld


IOC_TYPES = {
    "IP_ADDRESS": "IP Address",
    "DOMAIN": "Domain",
    "URL": "URL",
    "EMAIL_ADDRESS": "Email Address",
    "FILE_HASH": "File Hash",
    "FILE_NAME": "File Name",
}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
_FILE_NAME_RE = re.compile(r"^[^\s/\\<>:|?*]+\.[A-Za-z0-9]{1,10}$")

_SUSPICIOUS_TERMS = (
    "attacker",
    "admin",
    "support",
    "login",
    "verify",
    "reset",
    "invoice",
    "payment",
    "bank",
    "microsoft",
    "google",
    "paypal",
    "amazon",
    "crypto",
    "wallet",
    "password",
    "secure",
    "update",
    "urgent",
    "account",
    "document",
    "billing",
)

_BRAND_TERMS = (
    "microsoft",
    "google",
    "paypal",
    "amazon",
    "apple",
    "office365",
    "microsoft365",
)

_DISPOSABLE_EMAIL_PROVIDERS = (
    "mailinator.com",
    "tempmail.com",
    "10minutemail.com",
    "guerrillamail.com",
    "yopmail.com",
    "maildrop.cc",
    "dispostable.com",
    "temp-mail.org",
    "getnada.com",
    "fakeinbox.com",
    "sharklasers.com",
    "throwawaymail.com",
    "emailondeck.com",
    "mohmal.com",
)

_DANGEROUS_FILE_EXTENSIONS = (
    "exe",
    "scr",
    "js",
    "jse",
    "vbs",
    "vbe",
    "bat",
    "cmd",
    "ps1",
    "hta",
    "lnk",
    "iso",
    "img",
    "msi",
    "docm",
    "xlsm",
    "pptm",
    "zip",
    "rar",
    "7z",
    "gz",
    "tgz",
)

_LEET_TRANSLATION = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})


@dataclass(frozen=True)
class HeuristicConfig:
    suspicious_terms: tuple[str, ...]
    brand_terms: tuple[str, ...]
    disposable_email_providers: tuple[str, ...]
    dangerous_file_extensions: tuple[str, ...]
    suspicious_term_weight: int = 12
    brand_impersonation_weight: int = 18
    typosquatting_weight: int = 20
    disposable_provider_weight: int = 25
    excessive_numbers_weight: int = 8
    excessive_hyphens_weight: int = 8
    dangerous_extension_weight: int = 12
    similarity_threshold: float = 0.82
    digit_ratio_threshold: float = 0.35
    hyphen_threshold: int = 2


def _load_heuristic_config() -> HeuristicConfig:
    disposable_override = os.getenv("IOC_HEURISTIC_DISPOSABLE_DOMAINS", "").strip()
    disposable_domains = tuple(domain.strip().lower() for domain in disposable_override.split(",") if domain.strip()) or _DISPOSABLE_EMAIL_PROVIDERS
    return HeuristicConfig(
        suspicious_terms=_SUSPICIOUS_TERMS,
        brand_terms=_BRAND_TERMS,
        disposable_email_providers=disposable_domains,
        dangerous_file_extensions=_DANGEROUS_FILE_EXTENSIONS,
        similarity_threshold=float(os.getenv("IOC_HEURISTIC_SIMILARITY_THRESHOLD", "0.82")),
        digit_ratio_threshold=float(os.getenv("IOC_HEURISTIC_DIGIT_RATIO_THRESHOLD", "0.35")),
        hyphen_threshold=int(os.getenv("IOC_HEURISTIC_HYPHEN_THRESHOLD", "2")),
    )


def _normalize_for_matching(value: str) -> str:
    lowered = (value or "").lower().translate(_LEET_TRANSLATION)
    lowered = re.sub(r"[^a-z0-9]+", " ", lowered)
    return re.sub(r"\s+", " ", lowered).strip()


def _is_disposable_domain(domain: str, config: HeuristicConfig) -> bool:
    normalized_domain = (domain or "").lower().rstrip(".")
    return any(
        normalized_domain == provider or normalized_domain.endswith(f".{provider}") or normalized_domain.endswith(provider)
        for provider in config.disposable_email_providers
    )


def _score_keyword_terms(field_name: str, text: str, config: HeuristicConfig) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []
    normalized_text = _normalize_for_matching(text)
    if not normalized_text:
        return findings

    seen_terms: set[str] = set()
    for term in config.suspicious_terms:
        if term in seen_terms:
            continue
        term_normalized = _normalize_for_matching(term)
        if term_normalized and term_normalized in normalized_text:
            seen_terms.add(term)
            findings.append(
                {
                    "rule": "suspicious_term",
                    "field": field_name,
                    "match": term,
                    "score": config.suspicious_term_weight,
                    "detail": f"Matched suspicious term '{term}' in {field_name}.",
                }
            )
    return findings


def _score_structure(field_name: str, text: str, config: HeuristicConfig) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []
    compact = re.sub(r"\s+", "", text or "")
    if not compact:
        return findings

    digit_count = sum(character.isdigit() for character in compact)
    hyphen_count = compact.count("-")
    ratio = digit_count / len(compact) if compact else 0.0

    if digit_count >= 4 or ratio >= config.digit_ratio_threshold:
        findings.append(
            {
                "rule": "excessive_numbers",
                "field": field_name,
                "match": str(digit_count),
                "score": config.excessive_numbers_weight,
                "detail": f"{field_name} contains {digit_count} digit(s) with a ratio of {ratio:.2f}.",
            }
        )

    if hyphen_count >= config.hyphen_threshold:
        findings.append(
            {
                "rule": "excessive_hyphens",
                "field": field_name,
                "match": str(hyphen_count),
                "score": config.excessive_hyphens_weight,
                "detail": f"{field_name} contains {hyphen_count} hyphen(s).",
            }
        )

    return findings


def _score_typosquatting(host_text: str, config: HeuristicConfig) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []
    host_tokens = [token for token in re.split(r"[.\-_]+", _normalize_for_matching(host_text)) if token]
    compact_host = _normalize_for_matching(host_text).replace(" ", "")

    for brand in config.brand_terms:
        brand_normalized = _normalize_for_matching(brand).replace(" ", "")
        if not brand_normalized:
            continue

        if brand_normalized in compact_host and compact_host != brand_normalized:
            findings.append(
                {
                    "rule": "brand_impersonation",
                    "field": "domain",
                    "match": brand,
                    "score": config.brand_impersonation_weight,
                    "detail": f"Domain text references '{brand}' alongside additional characters or qualifiers.",
                }
            )

        for token in host_tokens:
            similarity = SequenceMatcher(None, token, brand_normalized).ratio()
            if similarity >= config.similarity_threshold and token != brand_normalized:
                findings.append(
                    {
                        "rule": "typosquatting",
                        "field": "domain",
                        "match": token,
                        "score": config.typosquatting_weight,
                        "detail": f"'{token}' is visually similar to '{brand}'.",
                    }
                )
                break

    return findings


def _score_file_name(file_name: str, config: HeuristicConfig) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []
    if not file_name:
        return findings

    stem = Path(file_name).stem
    extension = Path(file_name).suffix.lower().lstrip(".")
    if extension in config.dangerous_file_extensions:
        findings.append(
            {
                "rule": "dangerous_extension",
                "field": "file_name",
                "match": extension,
                "score": config.dangerous_extension_weight,
                "detail": f"File name uses a potentially dangerous '{extension}' extension.",
            }
        )

    findings.extend(_score_keyword_terms("file_name", stem, config))
    findings.extend(_score_structure("file_name", stem, config))
    return findings


def _split_url_components(value: str) -> Dict[str, str]:
    parsed = urlparse(value)
    path_parts = [part for part in parsed.path.split("/") if part]
    return {
        "host": parsed.netloc or "",
        "path": parsed.path or "",
        "query": parsed.query or "",
        "fragment": parsed.fragment or "",
        "file_name": path_parts[-1] if path_parts else "",
    }


def _score_heuristics(ioc_value: str, ioc_type: str, normalized: Dict[str, Any], config: Optional[HeuristicConfig] = None) -> Dict[str, Any]:
    config = config or _load_heuristic_config()
    findings: list[Dict[str, Any]] = []

    if ioc_type == IOC_TYPES["EMAIL_ADDRESS"]:
        local_part = ioc_value.split("@", 1)[0]
        domain = normalized.get("domain") or ioc_value.split("@")[-1]
        findings.extend(_score_keyword_terms("email_local_part", local_part, config))
        findings.extend(_score_structure("email_local_part", local_part, config))
        findings.extend(_score_keyword_terms("email_domain", domain, config))
        findings.extend(_score_structure("email_domain", domain, config))
        if _is_disposable_domain(domain, config):
            findings.append(
                {
                    "rule": "disposable_provider",
                    "field": "email_domain",
                    "match": domain,
                    "score": config.disposable_provider_weight,
                    "detail": f"Email domain '{domain}' matches a disposable or throwaway provider.",
                }
            )
        findings.extend(_score_typosquatting(domain, config))

    elif ioc_type == IOC_TYPES["DOMAIN"]:
        domain = normalized.get("host") or ioc_value
        findings.extend(_score_keyword_terms("domain", domain, config))
        findings.extend(_score_structure("domain", domain, config))
        findings.extend(_score_typosquatting(domain, config))
        if _is_disposable_domain(domain, config):
            findings.append(
                {
                    "rule": "disposable_provider",
                    "field": "domain",
                    "match": domain,
                    "score": config.disposable_provider_weight,
                    "detail": f"Domain '{domain}' matches a disposable or throwaway provider.",
                }
            )

    elif ioc_type == IOC_TYPES["URL"]:
        url_parts = _split_url_components(ioc_value)
        host = url_parts["host"]
        path = url_parts["path"]
        query = url_parts["query"]
        file_name = url_parts["file_name"]
        findings.extend(_score_keyword_terms("url_host", host, config))
        findings.extend(_score_structure("url_host", host, config))
        findings.extend(_score_typosquatting(host, config))
        findings.extend(_score_keyword_terms("url_path", path, config))
        findings.extend(_score_structure("url_path", path, config))
        findings.extend(_score_keyword_terms("url_query", query, config))
        findings.extend(_score_structure("url_query", query, config))
        if file_name:
            findings.extend(_score_file_name(file_name, config))
        if _is_disposable_domain(host, config):
            findings.append(
                {
                    "rule": "disposable_provider",
                    "field": "url_host",
                    "match": host,
                    "score": config.disposable_provider_weight,
                    "detail": f"URL host '{host}' matches a disposable or throwaway provider.",
                }
            )

    elif ioc_type == IOC_TYPES["FILE_NAME"]:
        file_name = normalized.get("basename") or Path(ioc_value).name or ioc_value
        findings.extend(_score_file_name(file_name, config))

    heuristic_score = min(100, sum(finding["score"] for finding in findings))
    return {
        "heuristic_score": heuristic_score,
        "heuristic_findings": findings,
        "heuristic_summary": "; ".join(finding["detail"] for finding in findings) if findings else "No heuristic IOC risk rules matched.",
    }


def detect_ioc_type(value: str) -> str:
    """Infer the IOC type from the provided value."""
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

    if cleaned.lower().startswith("md5:") or cleaned.lower().startswith("sha1:") or cleaned.lower().startswith("sha256:"):
        return IOC_TYPES["FILE_HASH"]

    if _HASH_RE.match(cleaned):
        return IOC_TYPES["FILE_HASH"]

    file_name_candidate = Path(cleaned).name
    if _FILE_NAME_RE.match(file_name_candidate):
        extension = Path(file_name_candidate).suffix.lower().lstrip(".")
        if extension in _DANGEROUS_FILE_EXTENSIONS or extension in {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "zip", "rar", "7z", "gz", "tar", "csv", "png", "jpg", "jpeg", "gif", "html", "htm", "svg", "iso", "img", "msi", "scr", "js", "vbs", "bat", "cmd", "ps1", "docm", "xlsm", "pptm"}:
            return IOC_TYPES["FILE_NAME"]

    if "." in cleaned and "/" not in cleaned:
        return IOC_TYPES["DOMAIN"]

    return IOC_TYPES["DOMAIN"]


def _normalize_value(ioc_type: str, value: str) -> Dict[str, Any]:
    normalized = {"type": ioc_type, "value": value.strip()}
    if ioc_type == IOC_TYPES["URL"]:
        parsed = urlparse(value)
        normalized.update(
            {
                "scheme": parsed.scheme or "",
                "host": parsed.netloc or "",
                "path": parsed.path or "",
            }
        )
    elif ioc_type == IOC_TYPES["DOMAIN"]:
        normalized.update({"host": value.strip().lower()})
    elif ioc_type == IOC_TYPES["EMAIL_ADDRESS"]:
        normalized.update({"domain": value.split("@")[-1].lower() if "@" in value else ""})
    elif ioc_type == IOC_TYPES["IP_ADDRESS"]:
        normalized.update({"version": "IPv4" if "." in value else "IPv6"})
    elif ioc_type == IOC_TYPES["FILE_HASH"]:
        normalized.update({"algorithm": "SHA256" if len(value.strip()) == 64 else "SHA1" if len(value.strip()) == 40 else "MD5"})
    elif ioc_type == IOC_TYPES["FILE_NAME"]:
        file_name = Path(value).name
        normalized.update(
            {
                "basename": file_name,
                "stem": Path(file_name).stem,
                "extension": Path(file_name).suffix.lower().lstrip("."),
            }
        )
    return normalized


def _get_whois_enrichment(ioc_type: str, value: str) -> Dict[str, Any]:
    if ioc_type not in {IOC_TYPES["DOMAIN"], IOC_TYPES["URL"]}:
        return {"status": "not_applicable", "details": "WHOIS is only applicable to domains and URLs."}

    host = value if ioc_type == IOC_TYPES["DOMAIN"] else urlparse(value).netloc
    created_at = get_whois_creation_date(host) if host else None
    return {
        "status": "ok" if created_at else "unavailable",
        "host": host,
        "created_at": created_at.isoformat() if created_at else None,
    }


def _get_dns_enrichment(ioc_type: str, value: str) -> Dict[str, Any]:
    if ioc_type not in {IOC_TYPES["DOMAIN"], IOC_TYPES["URL"]}:
        return {"status": "not_applicable", "details": "DNS enrichment is only applicable to domains and URLs."}

    host = value if ioc_type == IOC_TYPES["DOMAIN"] else urlparse(value).netloc
    records = get_dns_records(host) if host else {"A": [], "MX": [], "NS": []}
    return {
        "status": "ok" if records.get("A") or records.get("MX") or records.get("NS") else "unavailable",
        "records": records,
    }


def _get_abuseipdb_enrichment(ioc_type: str, value: str) -> Dict[str, Any]:
    if ioc_type != IOC_TYPES["IP_ADDRESS"]:
        return {"status": "not_applicable", "details": "AbuseIPDB integration is only designed for IP addresses."}

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"status": "not_configured", "details": "Set ABUSEIPDB_API_KEY to enable live enrichment."}
    return {"status": "simulated", "details": f"AbuseIPDB lookup would run for {value} using the configured API key."}


def _get_virustotal_enrichment(ioc_type: str, value: str) -> Dict[str, Any]:
    if ioc_type in {IOC_TYPES["URL"], IOC_TYPES["DOMAIN"], IOC_TYPES["IP_ADDRESS"], IOC_TYPES["FILE_HASH"]}:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return {"status": "not_configured", "details": "Set VIRUSTOTAL_API_KEY to enable live enrichment."}
        return {"status": "simulated", "details": f"VirusTotal lookup would run for {value} using the configured API key."}
    return {"status": "not_applicable", "details": "VirusTotal integration is designed for network and file indicators."}


def _get_otx_enrichment(ioc_type: str, value: str) -> Dict[str, Any]:
    if ioc_type in {IOC_TYPES["URL"], IOC_TYPES["DOMAIN"], IOC_TYPES["IP_ADDRESS"], IOC_TYPES["FILE_HASH"]}:
        api_key = os.getenv("OTX_API_KEY")
        if not api_key:
            return {"status": "not_configured", "details": "Set OTX_API_KEY to enable live enrichment."}
        return {"status": "simulated", "details": f"AlienVault OTX lookup would run for {value} using the configured API key."}
    return {"status": "not_applicable", "details": "AlienVault OTX integration is designed for network and file indicators."}


def _build_enrichment_map(ioc_type: str, value: str) -> Dict[str, Any]:
    return {
        "whois": _get_whois_enrichment(ioc_type, value),
        "dns": _get_dns_enrichment(ioc_type, value),
        "abuseipdb": _get_abuseipdb_enrichment(ioc_type, value),
        "virustotal": _get_virustotal_enrichment(ioc_type, value),
        "otx": _get_otx_enrichment(ioc_type, value),
    }


def assign_reputation_score(ioc_type: str, enrichment: Dict[str, Any]) -> int:
    """Assign a simple reputation score from 0 to 100."""
    score = 50
    if ioc_type == IOC_TYPES["IP_ADDRESS"]:
        score += 20
    elif ioc_type == IOC_TYPES["DOMAIN"]:
        score += 10
    elif ioc_type == IOC_TYPES["URL"]:
        score += 15
    elif ioc_type == IOC_TYPES["EMAIL_ADDRESS"]:
        score += 5

    whois = enrichment.get("whois", {})
    if whois.get("status") == "unavailable":
        score += 10
    if ioc_type in {IOC_TYPES["DOMAIN"], IOC_TYPES["URL"]}:
        dns = enrichment.get("dns", {})
        if dns.get("status") == "unavailable":
            score += 5

    if enrichment.get("abuseipdb", {}).get("status") == "simulated":
        score += 10
    if enrichment.get("virustotal", {}).get("status") == "simulated":
        score += 5
    if enrichment.get("otx", {}).get("status") == "simulated":
        score += 5

    return max(0, min(100, score))


def generate_ai_summary(ioc_type: str, normalized: Dict[str, Any], enrichment: Dict[str, Any], reputation_score: int, heuristic_findings: Optional[List[Dict[str, Any]]] = None) -> str:
    """Create a lightweight AI-style analyst summary from the normalized data."""
    if reputation_score >= 80:
        risk_phrase = "high-risk"
    elif reputation_score >= 60:
        risk_phrase = "moderate-risk"
    else:
        risk_phrase = "low-risk"

    sources = [name for name, entry in enrichment.items() if entry.get("status") not in {"not_applicable", "not_configured"}]
    summary = f"The {ioc_type.lower()} {normalized['value']} appears {risk_phrase}. Enrichment sources reviewed: {', '.join(sources) or 'none'}."
    if ioc_type == IOC_TYPES["IP_ADDRESS"]:
        summary += " Review the address against internal blocklists and network telemetry before any trust decision."
    elif ioc_type == IOC_TYPES["DOMAIN"]:
        summary += " Review domain registration details and DNS lifecycle signals for suspicious changes."
    elif ioc_type == IOC_TYPES["URL"]:
        summary += " Inspect the destination and any embedded redirects before clicking."
    elif ioc_type == IOC_TYPES["EMAIL_ADDRESS"]:
        summary += " Validate sender ownership and recent message activity."
    elif ioc_type == IOC_TYPES["FILE_NAME"]:
        summary += " Inspect the file name, extension, and surrounding context before opening."
    else:
        summary += " Validate the file hash against internal detections and known-good baselines."

    if heuristic_findings:
        top_rules = ", ".join(f"{finding['rule']} on {finding['field']}" for finding in heuristic_findings[:4])
        summary += f" Heuristic signals: {top_rules}."
    return summary


def normalize_ioc_analysis(ioc_value: str) -> Dict[str, Any]:
    """Normalize IOC data into a single response format suitable for UI and persistence."""
    ioc_type = detect_ioc_type(ioc_value)
    normalized = _normalize_value(ioc_type, ioc_value)
    enrichment = _build_enrichment_map(ioc_type, ioc_value)
    base_reputation_score = assign_reputation_score(ioc_type, enrichment)
    heuristic_result = _score_heuristics(ioc_value, ioc_type, normalized)
    heuristic_score = heuristic_result["heuristic_score"]
    reputation_score = max(base_reputation_score, min(100, int(round((base_reputation_score + heuristic_score) / 2))))
    summary = generate_ai_summary(ioc_type, normalized, enrichment, reputation_score, heuristic_result["heuristic_findings"])

    return {
        "ioc_value": ioc_value.strip(),
        "ioc_type": ioc_type,
        "normalized": normalized,
        "enrichment": enrichment,
        "base_reputation_score": base_reputation_score,
        "heuristic_score": heuristic_score,
        "heuristic_findings": heuristic_result["heuristic_findings"],
        "heuristic_summary": heuristic_result["heuristic_summary"],
        "reputation_score": reputation_score,
        "risk_score": reputation_score,
        "summary": summary,
    }


def analyze_ioc(ioc_value: str) -> Dict[str, Any]:
    """Analyze an IOC and return a normalized structure that can be persisted as an investigation case."""
    result = normalize_ioc_analysis(ioc_value)

    analyst_report = {
        "threat_level": "CRITICAL" if result["reputation_score"] >= 80 else "HIGH" if result["reputation_score"] >= 60 else "MEDIUM" if result["reputation_score"] >= 40 else "LOW",
        "confidence_percentage": result["reputation_score"],
        "executive_summary": result["summary"],
        "threat_assessment": f"IOC analysis for {result['ioc_type']} {result['ioc_value']} completed with a reputation score of {result['reputation_score']}.",
        "key_indicators": [
            {"indicator": result["ioc_type"], "severity": "HIGH" if result["reputation_score"] >= 60 else "MEDIUM", "finding": result["summary"], "weight": result["reputation_score"]}
        ],
        "detection_rationale": "Rule-based IOC enrichment pipeline with WHOIS, DNS, external-source placeholders, and heuristic IOC scoring.",
        "remediation_recommendations": [
            "Validate the IOC against internal telemetry.",
            "Review related alerts and endpoint activity.",
            "Escalate to the SOC if the score is high.",
        ],
        "heuristic_rules": result["heuristic_findings"],
        "heuristic_summary": result["heuristic_summary"],
        "base_reputation_score": result["base_reputation_score"],
    }

    result["analyst_report"] = analyst_report
    return result
