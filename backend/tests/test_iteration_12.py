"""Iteration 12: verify payload field coverage, KB adaptation, review-logs, no code fragments."""
import os, re, time, requests, pytest

BASE = os.environ.get("REACT_APP_BACKEND_URL")
if not BASE:
    for line in open("/app/frontend/.env"):
        if line.startswith("REACT_APP_BACKEND_URL="):
            BASE = line.split("=", 1)[1].strip()
BASE = BASE.rstrip("/")
API = f"{BASE}/api"


@pytest.fixture(scope="module")
def hdr():
    r = requests.post(f"{API}/auth/login",
                      json={"email": "admin@socpilot.ai", "password": "Admin@123"},
                      timeout=30)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _find_acme(hdr):
    r = requests.get(f"{API}/clients", headers=hdr, timeout=20)
    assert r.status_code == 200
    tenants = r.json()
    for t in tenants:
        blob = ((t.get("name") or "") + (t.get("slug") or "")).lower()
        if "acme" in blob:
            return t.get("id") or t.get("_id")
    return (tenants[0].get("id") or tenants[0].get("_id"))


def _find_offense(hdr, client_id, keywords):
    r = requests.get(f"{API}/offenses", headers=hdr,
                     params={"client_id": client_id}, timeout=30)
    assert r.status_code == 200
    for o in r.json():
        text = " ".join([str(o.get(k) or "") for k in
                         ("offense_name", "name", "rule_name", "description")]).lower()
        if all(k.lower() in text for k in keywords):
            return o.get("id") or o.get("_id") or o.get("offense_id")
    return None


def _wait_llm(hdr, off_id, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        d = requests.get(f"{API}/offenses/{off_id}", headers=hdr, timeout=20)
        assert d.status_code == 200
        rep = ((d.json().get("ai_analysis") or {}).get("mssp_report")) or {}
        gen = (rep.get("generated_by") or "").lower()
        if gen.startswith("llm") and (rep.get("analysis_lines") or []):
            return rep
        time.sleep(4)
    return None


def test_kb_present(hdr):
    r = requests.get(f"{API}/clients", headers=hdr, timeout=20)
    tenants = r.json()
    total = 0
    for t in tenants:
        cid = t.get("id") or t.get("_id")
        rr = requests.get(f"{API}/kb", headers=hdr, params={"client_id": cid}, timeout=20)
        if rr.status_code == 200:
            data = rr.json()
            entries = data if isinstance(data, list) else (data.get("entries") or data.get("items") or [])
            total += len(entries)
    print(f"Total KB entries: {total}")
    assert total > 0, "KB is empty — CSV import expected before test"


def test_powershell_offense_llm_report(hdr):
    client_id = _find_acme(hdr)
    off_id = _find_offense(hdr, client_id, ["powershell"])
    if not off_id:
        off_id = _find_offense(hdr, client_id, ["encoded"])
    assert off_id, "PowerShell offense not found on ACME"
    inv = requests.post(f"{API}/offenses/{off_id}/investigate",
                        headers=hdr, json={"engine": "llm"}, timeout=30)
    assert inv.status_code in (200, 202), inv.text
    rep = _wait_llm(hdr, off_id, 180)
    assert rep, "LLM report did not complete in 180s"

    # 1. Log source not CRE
    ls = (rep.get("log_source") or "")
    assert "custom rule engine" not in ls.lower(), f"CRE leaked: {ls}"
    print("log_source:", ls)

    # 2. Payload fields — check fields grid
    fields = rep.get("fields") or []
    labels = []
    if isinstance(fields, dict):
        labels = list(fields.keys())
    else:
        for f in fields:
            if isinstance(f, dict):
                labels.append(f.get("label", "") or f.get("name", ""))
            elif isinstance(f, (list, tuple)) and f:
                labels.append(str(f[0]))
            else:
                labels.append(str(f))
    joined_labels = " | ".join(labels).lower()
    print("field labels:", labels)
    # Expect Process, Parent Process, Command Line
    for req in ["process", "command"]:
        assert req in joined_labels, f"missing field '{req}' in {labels}"

    # 3. Recommendations contain review-logs pointer
    recs = rep.get("recommendations") or []
    rec_texts = [(r.get("text") if isinstance(r, dict) else str(r)) for r in recs]
    rec_texts = [t for t in rec_texts if t]
    print("recs:", rec_texts)
    assert any(re.search(r"review\s+the\b.*log", t, re.I) for t in rec_texts), \
        f"no 'Review the ... logs' pointer in recommendations"

    # 4. No code fragments in recommendations
    code_re = re.compile(r"(^\s*\$)|(::)|FromBase64|\bSystem\.[A-Z]|powershell\s+-\w|-enc\s|\benc\s+[A-Za-z0-9+/]{20,}", re.I)
    for t in rec_texts:
        assert not code_re.search(t), f"code fragment leaked in rec: {t!r}"

    # 5. Verdict + IOC
    assert rep.get("verdict"), "verdict missing"
    ioc = rep.get("ioc_enrichment") or {}
    print("verdict:", rep.get("verdict"), "ioc lines:", len(ioc.get("lines") or []))

    # 6. Analysis technical and offense-specific (no comparison)
    a = " ".join([(l.get("text") if isinstance(l, dict) else str(l))
                  for l in (rep.get("analysis_lines") or [])]).lower()
    for banned in ["similar incident", "historical", "previous offense", "compared to other"]:
        assert banned not in a
    print("analysis first 200:", a[:200])


def test_kb_adaptation_in_analysis(hdr):
    """When KB matches, analysis/impact/recs should mention offense-specific terms."""
    client_id = _find_acme(hdr)
    off_id = _find_offense(hdr, client_id, ["powershell"]) or _find_offense(hdr, client_id, ["encoded"])
    assert off_id
    d = requests.get(f"{API}/offenses/{off_id}", headers=hdr, timeout=20)
    rep = ((d.json().get("ai_analysis") or {}).get("mssp_report")) or {}
    all_text = " ".join([(l.get("text") if isinstance(l, dict) else str(l))
                         for l in (rep.get("analysis_lines") or [])
                         + (rep.get("impact_lines") or [])
                         + (rep.get("recommendations") or [])]).lower()
    # KB PowerShell entry should adapt — mention powershell or encoded
    assert "powershell" in all_text or "encoded" in all_text or "obfusc" in all_text, \
        f"KB adaptation not visible in text (first 400): {all_text[:400]}"
