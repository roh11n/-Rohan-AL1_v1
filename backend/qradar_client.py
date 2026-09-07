"""QRadar REST API client (Offenses + Ariel AQL)."""
import base64
import logging
import time
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class QRadarClient:
    def __init__(self, host: str, token: str, version: str = "12.0", verify_ssl: bool = False,
                 domain_id: int | None = None, processor_id: int | None = None):
        self.host = (host or "").rstrip("/")
        self.token = token
        self.version = version or "12.0"
        self.verify_ssl = verify_ssl
        self.domain_id = domain_id
        self.processor_id = processor_id

    def _headers(self, form: bool = False) -> dict:
        h = {"SEC": self.token, "Version": self.version, "Accept": "application/json"}
        if form:
            h["Content-Type"] = "application/x-www-form-urlencoded"
        return h

    def test_connection(self) -> dict:
        if not self.host or not self.token:
            return {"ok": False, "error": "Host or token missing"}
        try:
            r = requests.get(f"{self.host}/api/system/about", headers=self._headers(),
                             verify=self.verify_ssl, timeout=15)
            if r.status_code == 200:
                return {"ok": True, "info": r.json()}
            return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def fetch_offenses(self, filter_expr: str | None = None, limit: int = 50) -> list[dict]:
        params = {}
        parts = []
        if self.domain_id:
            parts.append(f"domain_id={self.domain_id}")
        if filter_expr:
            parts.append(filter_expr)
        if parts:
            params["filter"] = " and ".join(parts)
        headers = self._headers()
        headers["Range"] = f"items=0-{max(0, limit - 1)}"
        r = requests.get(f"{self.host}/api/siem/offenses", headers=headers, params=params,
                         verify=self.verify_ssl, timeout=60)
        r.raise_for_status()
        return r.json() if isinstance(r.json(), list) else []

    def run_aql(self, query: str, max_wait_s: int = 60) -> list[dict]:
        r = requests.post(f"{self.host}/api/ariel/searches", headers=self._headers(form=True),
                          data={"query_expression": query}, verify=self.verify_ssl, timeout=60)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"AQL create failed HTTP {r.status_code}: {r.text[:200]}")
        search_id = r.json().get("search_id")
        start = time.time()
        while True:
            if time.time() - start > max_wait_s:
                raise TimeoutError("AQL polling timeout")
            s = requests.get(f"{self.host}/api/ariel/searches/{search_id}", headers=self._headers(),
                             verify=self.verify_ssl, timeout=30)
            status = s.json().get("status")
            if status == "COMPLETED":
                break
            if status in ("ERROR", "CANCELED"):
                raise RuntimeError(f"AQL failed status={status}")
            time.sleep(2)
        res = requests.get(f"{self.host}/api/ariel/searches/{search_id}/results",
                           headers=self._headers(), verify=self.verify_ssl, timeout=60)
        res.raise_for_status()
        events = res.json().get("events", [])
        for e in events:
            payload = e.get("payload")
            if payload:
                try:
                    e["decoded_payload"] = base64.b64decode(payload).decode("utf-8", errors="ignore")
                except Exception:
                    e["decoded_payload"] = payload
        return events

    def build_aql_for_offense(self, offense_id: int, category_type: str = "generic",
                              start_time_ms: int | None = None) -> str:
        base_fields = {
            "generic": "sourceip, destinationip, username, payload, eventname, category, logsourcename",
            "authentication": "sourceip, destinationip, username, payload, eventname, category, \"AuthenticationPackage\", \"LogonType\"",
            "firewall": "sourceip, destinationip, username, payload, eventname, category, sourceport, destinationport, protocolname",
            "dns": "sourceip, destinationip, username, payload, eventname, category, \"URL Host\", \"DNS Query\"",
            "process": "sourceip, username, payload, eventname, category, \"Process Path\", \"Parent Process Path\", \"Command\"",
        }
        fields = base_fields.get(category_type, base_fields["generic"])
        return f"SELECT {fields} FROM events WHERE INOFFENSE({offense_id}) LAST 6 HOURS"

    def fetch_events_for_offense(self, offense_id: int, category_type: str = "generic",
                                 max_events: int = 50) -> list[dict]:
        query = self.build_aql_for_offense(offense_id, category_type)
        events = self.run_aql(query)
        return events[:max_events]
