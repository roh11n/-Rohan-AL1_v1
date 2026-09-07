"""Tests for MSSP-report-driven self-learning KB feature.

Covers:
- Meaningful MSSP edits ingest into per-tenant KB (analyst_feedback row + vectors).
- Trivial edits do not ingest.
- Close / Approve without MSSP edit increments accurate_confirmations, no KB row.
- Edit-then-close does NOT double count as confirmation.
"""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/")
API = f"{BASE_URL}/api"
ADMIN_EMAIL = "admin@socpilot.ai"
ADMIN_PASSWORD = "Admin@SOCPilot2026"


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=30)
    assert r.status_code == 200, r.text
    return r.json()["access_token"] if "access_token" in r.json() else r.json()["token"]


@pytest.fixture(scope="module")
def headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@pytest.fixture(scope="module")
def acme_client_id(headers):
    r = requests.get(f"{API}/clients", headers=headers, timeout=30)
    assert r.status_code == 200, r.text
    clients = r.json()
    acme = next((c for c in clients if (c.get("code") or "").upper() == "ACME"), None)
    assert acme, f"No ACME client found in {[c.get('code') for c in clients]}"
    return acme["id"]


@pytest.fixture(scope="module")
def acme_offenses(headers, acme_client_id):
    r = requests.get(f"{API}/offenses", headers=headers, params={"client_id": acme_client_id}, timeout=30)
    assert r.status_code == 200, r.text
    offs = [o for o in r.json() if o.get("client_id") == acme_client_id]
    assert len(offs) >= 4, f"Need >=4 ACME offenses, got {len(offs)}"
    return offs


def _kb_count(headers, client_id):
    r = requests.get(f"{API}/kb", headers=headers, params={"client_id": client_id}, timeout=30)
    assert r.status_code == 200, r.text
    return r.json()


def _investigate(headers, oid):
    r = requests.post(f"{API}/offenses/{oid}/investigate", headers=headers, timeout=120)
    # 200 fresh, or 409/400/429 possible; accept 200
    assert r.status_code == 200, f"investigate {oid} -> {r.status_code} {r.text}"
    return r.json()


def _get_offense(headers, oid):
    r = requests.get(f"{API}/offenses/{oid}", headers=headers, timeout=30)
    assert r.status_code == 200, r.text
    return r.json()


# ------------ Scenario 1: End-to-end edit path ------------
def test_meaningful_edit_ingests_into_kb(headers, acme_client_id, acme_offenses):
    # Prefer the brute-force one if available
    target = next((o for o in acme_offenses if "login failure" in (o.get("description") or "").lower()),
                  acme_offenses[0])
    oid = target["id"]
    _investigate(headers, oid)
    before = _kb_count(headers, acme_client_id)
    before_ids = {e["id"] for e in before}

    payload = {
        "verdict": "TP",
        "verdict_reason": "Confirmed brute force from same source IP",
        "analyst_notes": "Similar to CVE-2023-XXXX incident last quarter; user account should be locked and IP blocked at firewall.",
        "recommendations": ["Lock user account", "Block source IP at edge firewall", "Force password reset"],
    }
    r = requests.patch(f"{API}/offenses/{oid}/mssp-report", headers=headers, json=payload, timeout=60)
    assert r.status_code == 200, r.text
    updated = r.json()
    assert updated.get("mssp_edited") is True
    assert updated.get("mssp_last_edited_by") == ADMIN_EMAIL

    # Poll for new KB row up to ~15s
    new_entry = None
    deadline = time.time() + 15
    while time.time() < deadline:
        current = _kb_count(headers, acme_client_id)
        for e in current:
            if e["id"] not in before_ids and e.get("kb_type") == "analyst_feedback":
                new_entry = e
                break
        if new_entry and new_entry.get("status") in ("READY", "FAILED"):
            break
        time.sleep(1)

    assert new_entry is not None, "No new analyst_feedback KB row appeared"
    pytest.entry_status = new_entry.get("status")
    assert new_entry.get("status") == "READY", f"KB entry status={new_entry.get('status')} err={new_entry.get('error')}"
    assert new_entry.get("document_count", 0) >= 1

    # Search
    sr = requests.post(f"{API}/kb/search", headers=headers,
                       json={"client_id": acme_client_id, "query": "brute force login failure lock account", "n_results": 5},
                       timeout=60)
    assert sr.status_code == 200, sr.text
    matches = sr.json().get("matches", [])
    assert any((m.get("source") or "").startswith("feedback-") for m in matches), f"No feedback- source in matches: {matches}"
    text_all = " ".join((m.get("text") or "") + " " + (m.get("document") or "") for m in matches).lower()
    assert "lock" in text_all or "block source ip" in text_all or "brute" in text_all, f"Content not retrievable: {text_all[:400]}"

    # Save for scenario 2
    pytest.scenario1_oid = oid
    pytest.kb_count_after_s1 = len(_kb_count(headers, acme_client_id))


# ------------ Scenario 2: Trivial edit must NOT ingest ------------
def test_trivial_edit_does_not_ingest(headers, acme_client_id):
    oid = pytest.scenario1_oid
    before_count = pytest.kb_count_after_s1
    r = requests.patch(f"{API}/offenses/{oid}/mssp-report", headers=headers, json={"verdict": "TP"}, timeout=30)
    assert r.status_code == 200, r.text
    time.sleep(3)  # give any background task a moment to (not) fire
    after_count = len(_kb_count(headers, acme_client_id))
    assert after_count == before_count, f"KB count changed on trivial edit: {before_count} -> {after_count}"


# ------------ Scenario 3: No-edit-confirm via /close ------------
def test_close_without_edit_increments_confirmations(headers, acme_client_id, acme_offenses):
    used = {pytest.scenario1_oid}
    target = next(o for o in acme_offenses if o["id"] not in used)
    oid = target["id"]
    _investigate(headers, oid)
    before = _get_offense(headers, oid)
    assert (before.get("accurate_confirmations") or 0) == 0

    kb_before = len(_kb_count(headers, acme_client_id))

    r = requests.post(f"{API}/offenses/{oid}/close", headers=headers,
                      json={"closure_comments": "Confirmed benign per playbook", "closure_source": "analyst"},
                      timeout=30)
    assert r.status_code == 200, r.text

    after = _get_offense(headers, oid)
    assert after.get("accurate_confirmations") == 1, f"accurate_confirmations={after.get('accurate_confirmations')}"
    assert after.get("last_accurate_confirmation_by") == ADMIN_EMAIL

    time.sleep(2)
    kb_after = len(_kb_count(headers, acme_client_id))
    assert kb_after == kb_before, f"KB should not change on no-edit close: {kb_before}->{kb_after}"

    pytest.scenario3_oid = oid


# ------------ Scenario 4: No-edit-approve via /action ------------
def test_approve_via_action_increments_confirmations(headers, acme_client_id, acme_offenses):
    used = {pytest.scenario1_oid, pytest.scenario3_oid}
    target = next(o for o in acme_offenses if o["id"] not in used)
    oid = target["id"]
    _investigate(headers, oid)
    kb_before = len(_kb_count(headers, acme_client_id))

    r = requests.post(f"{API}/offenses/{oid}/action", headers=headers, json={"action": "approve"}, timeout=30)
    assert r.status_code == 200, r.text
    after = _get_offense(headers, oid)
    assert after.get("accurate_confirmations") == 1, f"accurate_confirmations={after.get('accurate_confirmations')}"

    time.sleep(2)
    kb_after = len(_kb_count(headers, acme_client_id))
    assert kb_after == kb_before, f"KB should not change on approve: {kb_before}->{kb_after}"

    pytest.scenario4_oid = oid


# ------------ Scenario 5: Edit-then-close does NOT double count ------------
def test_edit_then_close_does_not_confirm(headers, acme_client_id, acme_offenses):
    used = {pytest.scenario1_oid, pytest.scenario3_oid, pytest.scenario4_oid}
    target = next(o for o in acme_offenses if o["id"] not in used)
    oid = target["id"]
    _investigate(headers, oid)

    r = requests.patch(f"{API}/offenses/{oid}/mssp-report", headers=headers,
                       json={"verdict": "FP", "recommendations": ["Whitelist source", "Update detection rule"]},
                       timeout=30)
    assert r.status_code == 200, r.text
    assert r.json().get("mssp_edited") is True

    r2 = requests.post(f"{API}/offenses/{oid}/close", headers=headers,
                       json={"closure_comments": "Closed after analyst review", "closure_source": "analyst"},
                       timeout=30)
    assert r2.status_code == 200, r2.text

    after = _get_offense(headers, oid)
    assert (after.get("accurate_confirmations") or 0) == 0, \
        f"accurate_confirmations should stay 0 after edit-then-close, got {after.get('accurate_confirmations')}"
