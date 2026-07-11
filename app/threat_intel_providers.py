import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import json
import logging
from datetime import datetime, timezone

from .utils import get_dns_records, get_whois_creation_date
from .clients.virustotal_client import VirusTotalClient
from . import database as database_module
from .models_db import ThreatIntelCache


class BaseThreatIntelProvider:
    """Shared interface for all threat-intel enrichment providers."""

    name: str = "base"
    supported_ioc_types: List[str] = []

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.supported_ioc_types

    def enrich(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        raise NotImplementedError


class VirusTotalProvider(BaseThreatIntelProvider):
    name = "VirusTotal"
    supported_ioc_types = ["IP Address", "Domain", "URL", "File Hash"]

    def enrich(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        if not self.supports(ioc_type):
            return {"status": "not_applicable", "details": "VirusTotal is not applicable for this IOC type."}

        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return {"status": "not_configured", "details": "Set VIRUSTOTAL_API_KEY to enable live enrichment."}

        # Check cache first
        try:
            with database_module.SessionLocal() as session:
                cache = (
                    session.query(ThreatIntelCache)
                    .filter(ThreatIntelCache.provider_name == self.name)
                    .filter(ThreatIntelCache.ioc_type == ioc_type)
                    .filter(ThreatIntelCache.ioc_value == ioc_value)
                    .first()
                )
                if cache:
                    expire_at = cache.created_at.timestamp() + cache.ttl_seconds
                    if expire_at > datetime.now(timezone.utc).timestamp():
                        try:
                            return json.loads(cache.response_json or "{}")
                        except Exception:
                            logging.exception("Failed to parse cached VirusTotal response; falling back to live call")
        except Exception:
            logging.exception("Error while checking VirusTotal cache")

        client = VirusTotalClient(api_key=api_key)
        try:
            raw = {}
            if ioc_type == "Domain":
                raw = client.get_domain_report(ioc_value)
            elif ioc_type == "URL":
                raw = client.get_url_report(ioc_value)
            elif ioc_type == "IP Address":
                raw = client.get_ip_report(ioc_value)
            elif ioc_type == "File Hash":
                raw = client.get_file_report(ioc_value)

            data = raw.get("data") if isinstance(raw, dict) else None
            attributes = data.get("attributes", {}) if isinstance(data, dict) and data else {}
            last_stats = attributes.get("last_analysis_stats") if isinstance(attributes, dict) else {}

            malicious = last_stats.get("malicious", 0) if isinstance(last_stats, dict) else 0
            suspicious = last_stats.get("suspicious", 0) if isinstance(last_stats, dict) else 0
            harmless = last_stats.get("harmless", 0) if isinstance(last_stats, dict) else 0
            total_engines = sum(v for v in (malicious, suspicious, harmless) if isinstance(v, int)) or None

            engine_verdicts = {}
            if isinstance(attributes.get("last_analysis_results"), dict):
                for engine, entry in attributes.get("last_analysis_results", {}).items():
                    engine_verdicts[engine] = {
                        "category": entry.get("category"),
                        "method": entry.get("method"),
                        "result": entry.get("result"),
                    }

            last_analysis_date = attributes.get("last_analysis_date")
            reputation = attributes.get("reputation") if isinstance(attributes.get("reputation"), int) else None
            community_score = attributes.get("community_score") if isinstance(attributes.get("community_score"), int) else None
            permalink = (data.get("links", {}).get("self") if isinstance(data, dict) else None) or None

            provider_payload = {
                "status": "ok",
                "details": "VirusTotal enrichment returned",
                "data": {
                    "detection_ratio": f"{malicious}/{total_engines}" if total_engines else None,
                    "reputation": reputation,
                    "community_score": community_score,
                    "last_analysis_date": datetime.fromtimestamp(last_analysis_date, timezone.utc).isoformat() if isinstance(last_analysis_date, (int, float)) else last_analysis_date,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "engine_verdicts": engine_verdicts,
                    "permalink": permalink,
                },
            }

            # store cache
            try:
                ttl = 86400 if ioc_type in {"Domain", "URL", "IP Address"} else 604800
                with database_module.SessionLocal() as session:
                    entry = ThreatIntelCache(
                        provider_name=self.name,
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        response_json=json.dumps(provider_payload),
                        ttl_seconds=ttl,
                    )
                    session.add(entry)
                    session.commit()
            except Exception:
                logging.exception("Failed to write VirusTotal cache entry")

            return provider_payload
        except Exception as exc:
            logging.exception("VirusTotal provider error")
            return {"status": "error", "details": str(exc)}


class AbuseIPDBProvider(BaseThreatIntelProvider):
    name = "AbuseIPDB"
    supported_ioc_types = ["IP Address"]

    def enrich(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        if not self.supports(ioc_type):
            return {"status": "not_applicable", "details": "AbuseIPDB is only available for IP addresses."}
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return {"status": "not_configured", "details": "Set ABUSEIPDB_API_KEY to enable live enrichment."}
        return {"status": "simulated", "details": f"AbuseIPDB lookup would run for {ioc_value} using the configured API key."}


class AlienVaultOTXProvider(BaseThreatIntelProvider):
    name = "AlienVault OTX"
    supported_ioc_types = ["IP Address", "Domain", "URL", "File Hash"]

    def enrich(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        if not self.supports(ioc_type):
            return {"status": "not_applicable", "details": "AlienVault OTX is not applicable for this IOC type."}
        api_key = os.getenv("OTX_API_KEY")
        if not api_key:
            return {"status": "not_configured", "details": "Set OTX_API_KEY to enable live enrichment."}
        return {"status": "simulated", "details": f"AlienVault OTX lookup would run for {ioc_value} using the configured API key."}


class WhoisProvider(BaseThreatIntelProvider):
    name = "WHOIS"
    supported_ioc_types = ["Domain", "URL"]

    def enrich(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        if not self.supports(ioc_type):
            return {"status": "not_applicable", "details": "WHOIS enrichment is only available for domains and URLs."}
        host = ioc_value if ioc_type == "Domain" else urlparse(ioc_value).netloc
        created_at = get_whois_creation_date(host) if host else None
        return {
            "status": "ok" if created_at else "unavailable",
            "host": host,
            "created_at": created_at.isoformat() if created_at else None,
        }


class DnsProvider(BaseThreatIntelProvider):
    name = "DNS"
    supported_ioc_types = ["Domain", "URL"]

    def enrich(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        if not self.supports(ioc_type):
            return {"status": "not_applicable", "details": "DNS enrichment is only available for domains and URLs."}
        host = ioc_value if ioc_type == "Domain" else urlparse(ioc_value).netloc
        records = get_dns_records(host) if host else {"A": [], "MX": [], "NS": []}
        return {
            "status": "ok" if records.get("A") or records.get("MX") or records.get("NS") else "unavailable",
            "records": records,
        }
