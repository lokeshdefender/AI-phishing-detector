import base64
import time
from typing import Any, Dict, Optional

import requests


class VirusTotalClient:
    def __init__(self, api_key: str, base_url: str = "https://www.virustotal.com/api/v3", timeout: int = 10):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {self.api_key}"})

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        resp = self.session.get(url, params=params or {}, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        return self._get(f"/domains/{domain}")

    def get_ip_report(self, ip: str) -> Dict[str, Any]:
        return self._get(f"/ip_addresses/{ip}")

    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        return self._get(f"/files/{file_hash}")

    def get_url_report(self, url: str) -> Dict[str, Any]:
        # VirusTotal v3 expects the URL id to be base64url encoded without padding
        encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        try:
            return self._get(f"/urls/{encoded}")
        except Exception:
            # Fallback: submit for analysis then poll for result (best-effort synchronous)
            submit = self.session.post(f"{self.base_url}/urls", data={"url": url}, timeout=self.timeout)
            submit.raise_for_status()
            analysis_id = submit.json().get("data", {}).get("id")
            if not analysis_id:
                raise RuntimeError("VirusTotal did not return an analysis id for the URL")
            # Poll until ready or timeout
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                analysis = self._get(f"/analyses/{analysis_id}")
                if analysis.get("data", {}).get("attributes", {}).get("status") == "completed":
                    # After analysis completes, VT exposes the url object separately
                    # Try fetching the url resource
                    try:
                        return self._get(f"/urls/{encoded}")
                    except Exception:
                        return analysis
                time.sleep(1)
            return {"data": {"attributes": {"status": "timeout"}}}
