from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import os
from typing import Any, Dict, List

from ..threat_intel_providers import BaseThreatIntelProvider
from .registry import get_default_registry


class ThreatIntelEngine:
    """Orchestrates provider-based threat intelligence enrichment.

    Behavior:
    - Runs provider.enrich() for providers that support the IOC type.
    - Executes providers concurrently with per-provider timeout.
    - Catches provider exceptions and converts them into normalized payloads.
    - Returns a mapping provider_name -> provider_result.
    """

    def __init__(self, providers: List[BaseThreatIntelProvider] | None = None, max_workers: int | None = None):
        self.providers = providers if providers is not None else get_default_registry()
        # default worker pool size: min(5, number of providers)
        self.max_workers = max_workers or min(5, max(1, len(self.providers)))
        self.timeout = int(os.getenv("THREATINTEL_PROVIDER_TIMEOUT", "10"))

    def _wrap_result(self, provider: BaseThreatIntelProvider, result: Any) -> Dict[str, Any]:
        if isinstance(result, dict):
            return result
        return {"status": "error", "details": str(result)}

    def enrich(self, ioc_value: str, ioc_type: str) -> Dict[str, Dict[str, Any]]:
        results: Dict[str, Dict[str, Any]] = {}
        providers_to_run = [p for p in self.providers if p.supports(ioc_type)]

        if not providers_to_run:
            return {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            future_map = {}
            for provider in providers_to_run:
                future = ex.submit(provider.enrich, ioc_value, ioc_type)
                future_map[future] = provider

            for future in as_completed(future_map, timeout=self.timeout * len(future_map)):
                provider = future_map[future]
                try:
                    result = future.result(timeout=self.timeout)
                    results[provider.name] = self._wrap_result(provider, result)
                except Exception as exc:
                    logging.exception("Provider %s failed during enrich", provider.name)
                    results[provider.name] = {"status": "error", "details": str(exc)}

        return results
