"""SOCPilot AI - FastAPI backend."""
import os
import asyncio
import logging
import secrets
import string
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List

from dotenv import load_dotenv
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

from fastapi import FastAPI, APIRouter, Depends, HTTPException, UploadFile, File, Form, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from db import db, utcnow_iso
from models import (
    UserRole, UserCreate, UserUpdate, UserPublic, LoginRequest, TokenResponse, ChangePasswordRequest,
    Client, ClientCreate, Offense, OffenseActionRequest, KBEntry,
    Settings, QRadarSettings, LLMSettings, IntegrationCred,
    Ticket, TicketCreate, TicketApproval, TicketMerge, AuditLog,
)
from auth import (
    hash_password, verify_password, create_access_token, get_current_user, require_roles,
    login_throttle_check, login_throttle_record_failure, login_throttle_reset,
    enforce_rate_limit,
)
from sample_data import generate_sample_offenses
import soc_engine
import rag_store
import kb_ingest
from qradar_client import QRadarClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("socpilot")

app = FastAPI(title="SOCPilot AI")
api = APIRouter(prefix="/api")

# ---------- Utility ----------
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _audit(user_email: str, action: str, resource: str, resource_id: str | None = None,
                 details: dict | None = None):
    log = AuditLog(user_email=user_email, action=action, resource=resource,
                   resource_id=resource_id, details=details or {}).model_dump()
    await db.audit_logs.insert_one(log)


def _serialize(doc: dict | None, drop_fields: list[str] | None = None) -> dict | None:
    if not doc:
        return doc
    doc.pop("_id", None)
    if drop_fields:
        for f in drop_fields:
            doc.pop(f, None)
    return doc


# ---------- Tenant scoping ----------
ROLES_UNRESTRICTED = {UserRole.ADMIN, UserRole.SOC_MANAGER}


def _is_unrestricted(user: dict) -> bool:
    return user.get("role") in ROLES_UNRESTRICTED


def _tenant_filter(user: dict, requested_client_id: Optional[str]) -> dict:
    """Return a Mongo filter dict enforcing tenant scope for the caller.
    Admin / SOC Manager may access any tenant; other roles are restricted to
    their `tenant_ids`."""
    if _is_unrestricted(user):
        return {"client_id": requested_client_id} if requested_client_id else {}
    allowed = set(user.get("tenant_ids") or [])
    if requested_client_id:
        if requested_client_id not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Tenant access denied")
        return {"client_id": requested_client_id}
    if not allowed:
        # No tenants assigned → yield empty result set, not 500.
        return {"client_id": "__none__"}
    return {"client_id": {"$in": list(allowed)}}


def _assert_tenant_access(user: dict, client_id: Optional[str]) -> None:
    """Raise 403 unless the caller may operate on `client_id`."""
    if client_id is None:
        return
    if _is_unrestricted(user):
        return
    if client_id not in set(user.get("tenant_ids") or []):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Tenant access denied")


# ---------- Startup seed ----------
@app.on_event("startup")
async def _startup():
    seed_email = os.environ.get("SEED_ADMIN_EMAIL", "").strip().lower()
    seed_password = os.environ.get("SEED_ADMIN_PASSWORD", "").strip()
    seed_demo = os.environ.get("SEED_DEMO_USERS", "false").strip().lower() in ("1", "true", "yes")

    if seed_email and not await db.users.find_one({"email": seed_email}):
        must_reset = False
        if not seed_password:
            # Generate a strong random password; log ONCE and require reset on first login.
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            seed_password = "".join(secrets.choice(alphabet) for _ in range(20))
            must_reset = True
            logger.warning("=" * 72)
            logger.warning("SOCPilot AI — one-time admin bootstrap credentials generated:")
            logger.warning("  email:    %s", seed_email)
            logger.warning("  password: %s", seed_password)
            logger.warning("Change this password immediately via POST /api/auth/change-password.")
            logger.warning("Set SEED_ADMIN_PASSWORD in backend/.env to disable this notice.")
            logger.warning("=" * 72)
        await db.users.insert_one({
            "id": str(uuid.uuid4()),
            "email": seed_email,
            "name": "SOC Admin",
            "role": UserRole.ADMIN,
            "hashed_password": hash_password(seed_password),
            "active": True,
            "tenant_ids": [],  # unrestricted (admin)
            "must_reset_password": must_reset,
            "created_at": _now(),
        })
        logger.info("Seeded admin %s (must_reset_password=%s)", seed_email, must_reset)

    # Seed default clients
    if await db.clients.count_documents({}) == 0:
        clients_seed = [
            {"id": str(uuid.uuid4()), "name": "Acme Financial", "code": "ACME",
             "industry": "Banking & Finance", "contact_email": "soc@acme.example",
             "description": "Tier-1 MSSP customer with 24/7 monitoring.", "active": True, "created_at": _now()},
            {"id": str(uuid.uuid4()), "name": "Nova Health", "code": "NOVA",
             "industry": "Healthcare", "contact_email": "security@nova.example",
             "description": "HIPAA-scoped environment, 5000+ endpoints.", "active": True, "created_at": _now()},
            {"id": str(uuid.uuid4()), "name": "Orion Logistics", "code": "ORION",
             "industry": "Logistics", "contact_email": "it@orion.example",
             "description": "OT/ICS integrated network hierarchy.", "active": True, "created_at": _now()},
        ]
        await db.clients.insert_many(clients_seed)
        logger.info("Seeded %d clients", len(clients_seed))

    # Demo analyst — only seeded when explicitly requested (dev/preview only).
    if seed_demo and not await db.users.find_one({"email": "analyst@socpilot.ai"}):
        analyst_pw = os.environ.get("SEED_ANALYST_PASSWORD", "").strip() or "Analyst@123"
        all_tenant_ids = [c["id"] for c in await db.clients.find({}, {"id": 1, "_id": 0}).to_list(100)]
        await db.users.insert_one({
            "id": str(uuid.uuid4()),
            "email": "analyst@socpilot.ai",
            "name": "Alex Chen",
            "role": UserRole.L1,
            "hashed_password": hash_password(analyst_pw),
            "active": True,
            "tenant_ids": all_tenant_ids,
            "must_reset_password": False,
            "created_at": _now(),
        })
        logger.info("Seeded demo L1 analyst analyst@socpilot.ai (tenant_ids=%d)", len(all_tenant_ids))

    # Seed sample offenses for any client that has none
    all_clients = await db.clients.find({}, {"_id": 0}).to_list(100)
    for c in all_clients:
        if await db.offenses.count_documents({"client_id": c["id"]}) == 0:
            offs = generate_sample_offenses(c["id"], count=12)
            await db.offenses.insert_many(offs)
            logger.info("Seeded %d sample offenses for client %s", len(offs), c["code"])

    # Reset any KB entries left in PROCESSING from a previous crash/restart
    stuck = await db.kb_entries.find({"status": "PROCESSING"}, {"_id": 0}).to_list(200)
    for e in stuck:
        await db.kb_entries.update_one(
            {"id": e["id"]},
            {"$set": {"status": "FAILED",
                      "error": "Ingestion was interrupted (backend restart). Please re-upload the file.",
                      "completed_at": _now()}},
        )
    if stuck:
        logger.info("Marked %d stuck KB entries as FAILED", len(stuck))

    # Seed global settings
    if not await db.settings.find_one({"id": "global"}):
        await db.settings.insert_one(Settings().model_dump())


# ---------- Auth ----------
@api.post("/auth/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    email = req.email.lower().strip()
    login_throttle_check(email)
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(req.password, user.get("hashed_password", "")):
        login_throttle_record_failure(email)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    if not user.get("active", True):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account disabled")
    login_throttle_reset(email)
    token = create_access_token(user["email"], {"role": user["role"], "name": user["name"]})
    await _audit(user["email"], "login", "auth")
    return TokenResponse(
        access_token=token,
        user=UserPublic(id=user["id"], email=user["email"], name=user["name"],
                        role=user["role"], active=user["active"],
                        tenant_ids=user.get("tenant_ids") or [],
                        must_reset_password=user.get("must_reset_password", False),
                        created_at=user["created_at"]),
    )


@api.get("/auth/me", response_model=UserPublic)
async def me(user: dict = Depends(get_current_user)):
    return UserPublic(**user)


@api.post("/auth/change-password")
async def change_password(payload: ChangePasswordRequest, user: dict = Depends(get_current_user)):
    doc = await db.users.find_one({"email": user["email"]})
    if not doc or not verify_password(payload.current_password, doc.get("hashed_password", "")):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")
    if len(payload.new_password) < 10:
        raise HTTPException(400, "New password must be at least 10 characters")
    if payload.new_password == payload.current_password:
        raise HTTPException(400, "New password must differ from the current one")
    await db.users.update_one(
        {"email": user["email"]},
        {"$set": {"hashed_password": hash_password(payload.new_password),
                  "must_reset_password": False,
                  "password_changed_at": _now()}},
    )
    await _audit(user["email"], "change_password", "user", user.get("id"))
    return {"ok": True}


# ---------- Users (Admin) ----------
@api.get("/users")
async def list_users(user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER]))):
    docs = await db.users.find({}, {"hashed_password": 0, "_id": 0}).to_list(500)
    return docs


@api.post("/users", response_model=UserPublic)
async def create_user(payload: UserCreate, user: dict = Depends(require_roles([UserRole.ADMIN]))):
    if payload.role not in UserRole.ALL:
        raise HTTPException(400, "Invalid role")
    if await db.users.find_one({"email": payload.email}):
        raise HTTPException(400, "Email already exists")
    if len(payload.password) < 10:
        raise HTTPException(400, "Password must be at least 10 characters")
    doc = {
        "id": str(uuid.uuid4()),
        "email": payload.email.lower().strip(),
        "name": payload.name,
        "role": payload.role,
        "hashed_password": hash_password(payload.password),
        "active": True,
        "tenant_ids": payload.tenant_ids or [],
        "must_reset_password": False,
        "created_at": _now(),
    }
    await db.users.insert_one(doc)
    await _audit(user["email"], "create", "user", doc["id"], {"email": payload.email, "role": payload.role})
    return UserPublic(**{k: v for k, v in doc.items() if k != "hashed_password"})


@api.put("/users/{user_id}", response_model=UserPublic)
async def update_user(user_id: str, payload: UserUpdate,
                      user: dict = Depends(require_roles([UserRole.ADMIN]))):
    updates = {k: v for k, v in payload.model_dump(exclude_none=True).items()}
    if "password" in updates:
        if len(updates["password"]) < 10:
            raise HTTPException(400, "Password must be at least 10 characters")
        updates["hashed_password"] = hash_password(updates.pop("password"))
    if not updates:
        raise HTTPException(400, "No fields")
    await db.users.update_one({"id": user_id}, {"$set": updates})
    doc = await db.users.find_one({"id": user_id}, {"hashed_password": 0, "_id": 0})
    if not doc:
        raise HTTPException(404, "Not found")
    await _audit(user["email"], "update", "user", user_id, {k: (v if k != "password" else "***") for k, v in updates.items()})
    return UserPublic(**doc)


@api.delete("/users/{user_id}")
async def delete_user(user_id: str, user: dict = Depends(require_roles([UserRole.ADMIN]))):
    r = await db.users.delete_one({"id": user_id})
    await _audit(user["email"], "delete", "user", user_id)
    return {"deleted": r.deleted_count}


# ---------- Clients ----------
@api.get("/clients")
async def list_clients(user: dict = Depends(get_current_user)):
    if _is_unrestricted(user):
        return await db.clients.find({}, {"_id": 0}).to_list(500)
    allowed = user.get("tenant_ids") or []
    if not allowed:
        return []
    return await db.clients.find({"id": {"$in": allowed}}, {"_id": 0}).to_list(500)


@api.post("/clients", response_model=Client)
async def create_client(payload: ClientCreate,
                        user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER]))):
    if await db.clients.find_one({"code": payload.code}):
        raise HTTPException(400, "Client code already exists")
    c = Client(**payload.model_dump())
    await db.clients.insert_one(c.model_dump())
    await _audit(user["email"], "create", "client", c.id, {"name": c.name})
    return c


@api.put("/clients/{client_id}", response_model=Client)
async def update_client(client_id: str, payload: ClientCreate,
                        user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER]))):
    updates = payload.model_dump()
    await db.clients.update_one({"id": client_id}, {"$set": updates})
    doc = await db.clients.find_one({"id": client_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Not found")
    await _audit(user["email"], "update", "client", client_id)
    return Client(**doc)


@api.delete("/clients/{client_id}")
async def delete_client(client_id: str,
                        user: dict = Depends(require_roles([UserRole.ADMIN]))):
    await db.clients.delete_one({"id": client_id})
    await db.offenses.delete_many({"client_id": client_id})
    await db.kb_entries.delete_many({"client_id": client_id})
    rag_store.delete_for_client(client_id)
    await _audit(user["email"], "delete", "client", client_id)
    return {"deleted": True}


# ---------- Dashboard ----------
@api.get("/dashboard/metrics")
async def dashboard(client_id: Optional[str] = None, user: dict = Depends(get_current_user)):
    q = _tenant_filter(user, client_id)
    offenses = await db.offenses.find(q, {"_id": 0}).to_list(2000)
    by_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    by_status = {"OPEN": 0, "INVESTIGATING": 0, "PENDING_APPROVAL": 0, "RESOLVED": 0, "CLOSED": 0}
    total_risk = 0
    analyzed = 0
    today = datetime.now(timezone.utc).date().isoformat()
    today_incidents = 0
    fp_count = 0
    tickets = await db.tickets.count_documents({
        "status": "PENDING_APPROVAL",
        **(_tenant_filter(user, client_id)),
    })
    trend: dict[str, int] = {}
    for i in range(6, -1, -1):
        d = (datetime.now(timezone.utc) - timedelta(days=i)).date().isoformat()
        trend[d] = 0
    for o in offenses:
        by_sev[o.get("severity_label", "Low")] = by_sev.get(o.get("severity_label", "Low"), 0) + 1
        by_status[o.get("status", "OPEN")] = by_status.get(o.get("status", "OPEN"), 0) + 1
        if o.get("ai_analysis"):
            analyzed += 1
            total_risk += int(o.get("risk_score", 0))
        if str(o.get("created_at", "")).startswith(today):
            today_incidents += 1
        if o.get("recommendation") == "False Positive":
            fp_count += 1
        d = str(o.get("created_at", ""))[:10]
        if d in trend:
            trend[d] += 1
    automation_rate = round((analyzed / max(1, len(offenses))) * 100, 1)
    fp_rate = round((fp_count / max(1, analyzed or 1)) * 100, 1) if analyzed else 0
    avg_risk = round(total_risk / max(1, analyzed), 1) if analyzed else 0
    return {
        "total_offenses": len(offenses),
        "by_severity": by_sev,
        "by_status": by_status,
        "today_incidents": today_incidents,
        "pending_approval": tickets,
        "automation_rate": automation_rate,
        "false_positive_rate": fp_rate,
        "average_risk": avg_risk,
        "mtta_minutes": 8,   # placeholder — computed once actions have timestamps
        "mttr_minutes": 42,  # placeholder
        "trend_7d": [{"date": k, "count": v} for k, v in trend.items()],
    }


# ---------- Offenses ----------
@api.get("/offenses")
async def list_offenses(client_id: Optional[str] = None, severity: Optional[str] = None,
                        status_filter: Optional[str] = None, limit: int = 200,
                        user: dict = Depends(get_current_user)):
    q = _tenant_filter(user, client_id)
    if severity:
        q["severity_label"] = severity
    if status_filter:
        q["status"] = status_filter
    docs = await db.offenses.find(q, {"_id": 0, "events": 0}).sort("last_updated", -1).to_list(limit)
    return docs


@api.get("/offenses/{offense_id}")
async def get_offense(offense_id: str, user: dict = Depends(get_current_user)):
    doc = await db.offenses.find_one({"id": offense_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Offense not found")
    _assert_tenant_access(user, doc.get("client_id"))
    return doc


@api.post("/offenses/{offense_id}/investigate")
async def investigate_offense(offense_id: str, user: dict = Depends(require_roles(
        [UserRole.ADMIN, UserRole.SOC_MANAGER, UserRole.L1, UserRole.L2, UserRole.L3]))):
    enforce_rate_limit(user["email"], "investigate", limit=30, window_seconds=3600)
    doc = await db.offenses.find_one({"id": offense_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Offense not found")
    _assert_tenant_access(user, doc.get("client_id"))

    # KB matches (broader retrieval so verdict logic sees more historical context)
    kb_matches = []
    try:
        query_text = f"{doc.get('description','')} {' '.join(doc.get('rules',[]))} {' '.join(doc.get('categories',[]))}"
        kb_matches = rag_store.query(doc["client_id"], query_text, n_results=8)
        # Additional targeted query to help FP/TP classification
        verdict_hint_query = f"{doc.get('description','')} closed false positive resolved"
        extra = rag_store.query(doc["client_id"], verdict_hint_query, n_results=4)
        seen = {m.get("text") for m in kb_matches}
        for m in extra:
            if m.get("text") not in seen:
                kb_matches.append(m)
    except Exception as e:
        logger.warning("KB RAG failed: %s", e)

    # Similar historical offenses (same client, past 30 days, not this one)
    others = await db.offenses.find(
        {"client_id": doc["client_id"], "id": {"$ne": offense_id}},
        {"_id": 0}
    ).sort("created_at", -1).limit(100).to_list(100)
    similar = []
    for o in others:
        sim = soc_engine.offense_similarity(doc, o)
        if sim >= 30:
            similar.append({
                "id": o["id"], "description": o["description"], "similarity": sim,
                "recommendation": o.get("recommendation"),
                "was_false_positive": o.get("recommendation") == "False Positive",
                "created_at": o.get("created_at"),
            })
    similar.sort(key=lambda x: x["similarity"], reverse=True)
    similar = similar[:5]

    # Optional LLM narrative
    settings_doc = await db.settings.find_one({"id": "global"}, {"_id": 0}) or {}
    llm_cfg = settings_doc.get("llm", {})
    ti_cfg = settings_doc.get("threat_intel", {})
    narrative = None
    if llm_cfg.get("enable_llm"):
        iocs_pre = soc_engine.extract_iocs("\n".join([str(doc.get(k, "")) for k in ("description",)] +
                                                     [str(e.get("payload", "")) for e in doc.get("events", [])]))
        mitre_pre = soc_engine.map_mitre(doc.get("description", ""), doc.get("categories", []))
        risk_pre = soc_engine.compute_risk_score(doc, mitre_pre, iocs_pre)
        rec_pre, _ = soc_engine.recommend(risk_pre, mitre_pre, doc)
        narrative = soc_engine.llm_narrative(doc, iocs_pre, mitre_pre, risk_pre, rec_pre,
                                             llm_cfg.get("model_name", "TinyLlama/TinyLlama-1.1B-Chat-v1.0"))

    # Load learned rule adjustments (Analyst Coach)
    adj_docs = await db.learned_adjustments.find({}, {"_id": 0}).to_list(500)
    learned_adjustments = {a["rule"]: a for a in adj_docs}

    analysis = soc_engine.analyze_offense(doc, kb_matches=kb_matches, similar=similar,
                                          llm_narrative=narrative, ti_settings=ti_cfg,
                                          learned_adjustments=learned_adjustments)

    updates = {
        "ai_analysis": analysis,
        "risk_score": analysis["risk_score"],
        "mitre_techniques": analysis["mitre"],
        "iocs": analysis["iocs"],
        "recommendation": analysis["recommended_action"],
        "confidence": analysis["confidence"],
        "similar_incidents": similar,
        "kb_matches": kb_matches,
        "status": "INVESTIGATING" if doc.get("status") == "OPEN" else doc.get("status"),
        "last_updated": _now(),
    }
    await db.offenses.update_one({"id": offense_id}, {"$set": updates})
    await _audit(user["email"], "investigate", "offense", offense_id, {"risk": analysis["risk_score"]})
    new_doc = await db.offenses.find_one({"id": offense_id}, {"_id": 0})
    return new_doc


class OffenseCloseRequest(BaseModel):
    closure_comments: str
    closure_source: str = "analyst"  # analyst | xsoar | duplicate


class OffenseEscalateRequest(BaseModel):
    client_contact: str = ""
    notes: str = ""


@api.post("/offenses/{offense_id}/escalate")
async def escalate_offense(offense_id: str, req: OffenseEscalateRequest,
                            user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER, UserRole.L1, UserRole.L2, UserRole.L3]))):
    off = await db.offenses.find_one({"id": offense_id}, {"_id": 0})
    if not off:
        raise HTTPException(404, "Offense not found")
    _assert_tenant_access(user, off.get("client_id"))
    updates = {
        "status": "ESCALATED",
        "escalated_at": _now(),
        "escalated_by": user["email"],
        "escalation_client_contact": req.client_contact,
        "escalation_notes": req.notes,
        "last_updated": _now(),
    }
    await db.offenses.update_one({"id": offense_id}, {"$set": updates})
    await _audit(user["email"], "escalate", "offense", offense_id, {"contact": req.client_contact})
    return await db.offenses.find_one({"id": offense_id}, {"_id": 0})


@api.post("/offenses/{offense_id}/close")
async def close_offense(offense_id: str, req: OffenseCloseRequest,
                        user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER, UserRole.L1, UserRole.L2, UserRole.L3]))):
    off = await db.offenses.find_one({"id": offense_id}, {"_id": 0})
    if not off:
        raise HTTPException(404, "Offense not found")
    _assert_tenant_access(user, off.get("client_id"))
    updates = {
        "status": "CLOSED",
        "closed_at": _now(),
        "closed_by": user["email"],
        "closure_comments": req.closure_comments,
        "closure_source": req.closure_source,
        "closing_reason": req.closure_comments[:200],
        "last_updated": _now(),
    }
    await db.offenses.update_one({"id": offense_id}, {"$set": updates})
    await _audit(user["email"], "close", "offense", offense_id,
                 {"source": req.closure_source, "comments_len": len(req.closure_comments)})
    # Feed the coach model
    await db.feedback.insert_one({
        "id": str(uuid.uuid4()), "offense_id": offense_id, "user": user["email"],
        "action": "close", "reason": req.closure_comments[:200],
        "closure_source": req.closure_source,
        "original_recommendation": off.get("recommendation"),
        "original_risk": off.get("risk_score", 0),
        "rules": off.get("rules") or [],
        "severity_label": off.get("severity_label"),
        "created_at": _now(),
    })
    return await db.offenses.find_one({"id": offense_id}, {"_id": 0})


class OffenseStatusRequest(BaseModel):
    status: str  # OPEN | INVESTIGATING | PENDING_APPROVAL | RESOLVED | CLOSED | ESCALATED
    closure_comments: Optional[str] = None
    closure_source: str = "analyst"


class BulkStatusRequest(BaseModel):
    offense_ids: List[str]
    status: str
    closure_comments: Optional[str] = None
    closure_source: str = "analyst"


VALID_STATUSES = {"OPEN", "INVESTIGATING", "PENDING_APPROVAL", "RESOLVED", "CLOSED", "ESCALATED"}


async def _apply_status_change(offense_id: str, new_status: str, user_email: str,
                                closure_comments: Optional[str] = None,
                                closure_source: str = "analyst") -> dict | None:
    off = await db.offenses.find_one({"id": offense_id}, {"_id": 0})
    if not off:
        return None
    updates: dict = {"status": new_status, "last_updated": _now()}
    if new_status == "CLOSED":
        if not (closure_comments or "").strip():
            raise HTTPException(400, f"closure_comments required to close offense {offense_id}")
        updates.update({
            "closed_at": _now(), "closed_by": user_email,
            "closure_comments": closure_comments, "closure_source": closure_source,
            "closing_reason": closure_comments[:200],
        })
        await db.feedback.insert_one({
            "id": str(uuid.uuid4()), "offense_id": offense_id, "user": user_email,
            "action": "close", "reason": closure_comments[:200],
            "closure_source": closure_source,
            "original_recommendation": off.get("recommendation"),
            "original_risk": off.get("risk_score", 0),
            "rules": off.get("rules") or [],
            "severity_label": off.get("severity_label"),
            "created_at": _now(),
        })
    elif new_status == "ESCALATED":
        updates.update({"escalated_at": _now(), "escalated_by": user_email})
    await db.offenses.update_one({"id": offense_id}, {"$set": updates})
    await _audit(user_email, f"status_change:{new_status}", "offense", offense_id,
                 {"comments_len": len(closure_comments or "")})
    return await db.offenses.find_one({"id": offense_id}, {"_id": 0})


@api.post("/offenses/{offense_id}/status")
async def change_offense_status(offense_id: str, req: OffenseStatusRequest,
                                 user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER, UserRole.L1, UserRole.L2, UserRole.L3]))):
    if req.status not in VALID_STATUSES:
        raise HTTPException(400, f"Invalid status. Allowed: {sorted(VALID_STATUSES)}")
    existing = await db.offenses.find_one({"id": offense_id}, {"_id": 0, "client_id": 1})
    if not existing:
        raise HTTPException(404, "Offense not found")
    _assert_tenant_access(user, existing.get("client_id"))
    doc = await _apply_status_change(offense_id, req.status, user["email"],
                                     req.closure_comments, req.closure_source)
    if not doc:
        raise HTTPException(404, "Offense not found")
    return doc


@api.post("/offenses/bulk-status")
async def bulk_change_status(req: BulkStatusRequest,
                              user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER, UserRole.L1, UserRole.L2, UserRole.L3]))):
    if req.status not in VALID_STATUSES:
        raise HTTPException(400, f"Invalid status. Allowed: {sorted(VALID_STATUSES)}")
    if not req.offense_ids:
        raise HTTPException(400, "offense_ids required")
    if req.status == "CLOSED" and not (req.closure_comments or "").strip():
        raise HTTPException(400, "closure_comments required when closing offenses")
    # Pre-fetch to validate tenant membership before any mutation
    offs = await db.offenses.find({"id": {"$in": req.offense_ids}}, {"_id": 0, "id": 1, "client_id": 1}).to_list(len(req.offense_ids))
    for o in offs:
        _assert_tenant_access(user, o.get("client_id"))
    allowed_ids = {o["id"] for o in offs}
    updated_ids: list[str] = []
    for oid in req.offense_ids:
        if oid not in allowed_ids:
            continue
        try:
            doc = await _apply_status_change(oid, req.status, user["email"],
                                             req.closure_comments, req.closure_source)
            if doc:
                updated_ids.append(oid)
        except HTTPException:
            continue
    return {"updated": len(updated_ids), "offense_ids": updated_ids}


class VTLookupRequest(BaseModel):
    artifact_type: str  # ip | hash | domain | url
    value: str


@api.post("/offenses/{offense_id}/vt-lookup")
async def vt_lookup(offense_id: str, req: VTLookupRequest,
                     user: dict = Depends(require_roles(
                         [UserRole.ADMIN, UserRole.SOC_MANAGER, UserRole.L1, UserRole.L2, UserRole.L3]))):
    """Query VirusTotal for a single artifact on demand. Result is persisted onto
    the offense (offense.vt_lookups[value]) and injected into ai_analysis.mssp_report
    so the MSSP export includes the VT verdict."""
    enforce_rate_limit(user["email"], "vt_lookup", limit=60, window_seconds=3600)
    off = await db.offenses.find_one({"id": offense_id}, {"_id": 0})
    if not off:
        raise HTTPException(404, "Offense not found")
    _assert_tenant_access(user, off.get("client_id"))
    settings_doc = await db.settings.find_one({"id": "global"}, {"_id": 0}) or {}
    ti = settings_doc.get("threat_intel") or {}
    from threat_intel import parse_vt_keys, vt_ip, vt_hash, vt_domain
    vt_keys = parse_vt_keys(ti.get("virustotal_api_keys", ""),
                            ti.get("virustotal_api_key", "")) if ti.get("virustotal_enabled") else []
    if not vt_keys:
        raise HTTPException(400, "VirusTotal not configured. Enable it and add API key(s) in Settings → Threat Intel.")

    a_type = (req.artifact_type or "").lower()
    value = (req.value or "").strip()
    if not value:
        raise HTTPException(400, "value is required")

    try:
        if a_type == "ip":
            result = vt_ip(value, vt_keys)
        elif a_type == "hash":
            result = vt_hash(value, vt_keys)
        elif a_type in ("domain", "url"):
            # Strip protocol if URL
            v = value
            if v.startswith("http"):
                from urllib.parse import urlparse
                v = urlparse(v).hostname or v
            result = vt_domain(v, vt_keys)
        else:
            raise HTTPException(400, "artifact_type must be one of: ip | hash | domain | url")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"VirusTotal lookup failed: {e}")

    if result is None:
        result = {"error": "VirusTotal returned no data (unknown artifact, quota reached, or invalid key)."}

    # Persist per-artifact result
    vt_lookups = off.get("vt_lookups") or {}
    key = f"{a_type}:{value}"
    entry = {
        "artifact_type": a_type,
        "value": value,
        "result": result,
        "queried_at": _now(),
        "queried_by": user["email"],
    }
    vt_lookups[key] = entry
    updates = {"vt_lookups": vt_lookups, "last_updated": _now()}

    # Inject into MSSP report so downstream tickets carry the VT verdict
    ai = off.get("ai_analysis") or {}
    if ai:
        mssp = ai.get("mssp_report") or {}
        vt_list = mssp.get("vt_lookups") or []
        # de-dupe by (type, value)
        vt_list = [x for x in vt_list if not (x.get("artifact_type") == a_type and x.get("value") == value)]
        vt_list.append(entry)
        mssp["vt_lookups"] = vt_list
        ai["mssp_report"] = mssp
        updates["ai_analysis"] = ai

    await db.offenses.update_one({"id": offense_id}, {"$set": updates})
    await _audit(user["email"], "vt_lookup", "offense", offense_id,
                 {"artifact": key, "malicious": (result or {}).get("malicious")})
    return {"entry": entry, "offense": await db.offenses.find_one({"id": offense_id}, {"_id": 0})}


@api.get("/offenses/{offense_id}/duplicates")
async def offense_duplicates(offense_id: str, user: dict = Depends(get_current_user)):
    """Find previously-closed offenses in the same client that share artefacts
    (rule + at least one source IP or username). Returns candidates the analyst
    can quickly close the current offense against."""
    off = await db.offenses.find_one({"id": offense_id}, {"_id": 0})
    if not off:
        raise HTTPException(404, "Offense not found")
    _assert_tenant_access(user, off.get("client_id"))
    rules = off.get("rules") or []
    src_ips = off.get("source_ips") or []
    users = off.get("usernames") or []
    if not rules and not src_ips and not users:
        return {"duplicates": []}
    q: dict = {
        "client_id": off["client_id"],
        "id": {"$ne": offense_id},
        "status": "CLOSED",
    }
    or_clauses = []
    if rules:
        or_clauses.append({"rules": {"$in": rules}})
    if src_ips:
        or_clauses.append({"source_ips": {"$in": src_ips}})
    if users:
        or_clauses.append({"usernames": {"$in": users}})
    if or_clauses:
        q["$or"] = or_clauses
    cands = await db.offenses.find(q, {"_id": 0}).sort("closed_at", -1).limit(10).to_list(10)
    dupes = []
    for c in cands:
        overlap = {
            "rules": list(set(rules) & set(c.get("rules") or [])),
            "source_ips": list(set(src_ips) & set(c.get("source_ips") or [])),
            "usernames": list(set(users) & set(c.get("usernames") or [])),
        }
        if not any(overlap.values()):
            continue
        dupes.append({
            "id": c["id"],
            "qradar_offense_id": c.get("qradar_offense_id"),
            "description": c.get("description"),
            "closed_at": c.get("closed_at"),
            "closed_by": c.get("closed_by"),
            "closure_comments": c.get("closure_comments"),
            "closure_source": c.get("closure_source"),
            "recommendation": c.get("recommendation"),
            "overlap": overlap,
        })
    return {"duplicates": dupes}


@api.post("/offenses/{offense_id}/action")
async def offense_action(offense_id: str, req: OffenseActionRequest,
                         user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER, UserRole.L1, UserRole.L2, UserRole.L3]))):
    action = req.action.lower()
    off_before = await db.offenses.find_one({"id": offense_id}, {"_id": 0})
    if not off_before:
        raise HTTPException(404, "Offense not found")
    _assert_tenant_access(user, off_before.get("client_id"))
    updates = {"last_updated": _now()}
    if action == "approve":
        updates["status"] = "RESOLVED"
    elif action == "reject":
        updates["status"] = "OPEN"
        updates["recommendation"] = None
        updates["ai_analysis"] = None
    elif action == "escalate":
        updates["status"] = "INVESTIGATING"
        updates["recommendation"] = "Escalate L3"
    elif action == "close":
        updates["status"] = "CLOSED"
        updates["closing_reason"] = req.reason or "Closed by analyst"
    elif action == "modify":
        if req.modified_recommendation:
            updates["recommendation"] = req.modified_recommendation
    else:
        raise HTTPException(400, "Unknown action")
    await db.offenses.update_one({"id": offense_id}, {"$set": updates})
    await _audit(user["email"], action, "offense", offense_id, {"reason": req.reason})

    # Record analyst feedback for Coach
    fb = {
        "id": str(uuid.uuid4()),
        "offense_id": offense_id,
        "user": user["email"],
        "action": action,
        "reason": req.reason,
        "modified": req.modified_recommendation,
        "original_recommendation": off_before.get("recommendation"),
        "original_risk": off_before.get("risk_score", 0),
        "rules": off_before.get("rules") or [],
        "severity_label": off_before.get("severity_label"),
        "created_at": _now(),
    }
    await db.feedback.insert_one(fb)

    # Learned adjustments: gentle nudge per rule
    # approve/close accepting a HIGH-risk recommendation → keep as-is
    # reject on high risk → -5 delta (rule too noisy)
    # approve on low risk close-benign → -3 (system slightly over-alerting)
    # escalate action → +4 (analysts want more attention on this rule)
    delta_map = {"reject": -5, "escalate": +4, "close": -2, "approve": +2, "modify": 0}
    delta = delta_map.get(action, 0)
    if delta != 0:
        for rule in off_before.get("rules") or []:
            await db.learned_adjustments.update_one(
                {"rule": rule},
                {"$inc": {"risk_delta": delta, "feedback_count": 1},
                 "$set": {"last_updated": _now(), "last_action": action, "last_user": user["email"]}},
                upsert=True,
            )
            # Clamp delta between -25 and +25 to keep model stable
            adj = await db.learned_adjustments.find_one({"rule": rule})
            if adj:
                clamped = max(-25, min(25, int(adj.get("risk_delta") or 0)))
                if clamped != adj.get("risk_delta"):
                    await db.learned_adjustments.update_one({"rule": rule}, {"$set": {"risk_delta": clamped}})

    doc = await db.offenses.find_one({"id": offense_id}, {"_id": 0})
    return doc


@api.get("/coach/insights")
async def coach_insights(user: dict = Depends(get_current_user)):
    """Analyst Coach: aggregated feedback + learned adjustments."""
    feedback = await db.feedback.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    by_action: dict[str, int] = {}
    by_user: dict[str, int] = {}
    for f in feedback:
        a = f.get("action", "unknown")
        by_action[a] = by_action.get(a, 0) + 1
        u = f.get("user", "unknown")
        by_user[u] = by_user.get(u, 0) + 1
    adjustments = await db.learned_adjustments.find({}, {"_id": 0}).sort("feedback_count", -1).to_list(100)
    return {
        "total_feedback": len(feedback),
        "by_action": by_action,
        "by_user": by_user,
        "adjustments": adjustments,
        "recent_feedback": feedback[:20],
    }


@api.post("/coach/reset")
async def coach_reset(user: dict = Depends(require_roles([UserRole.ADMIN]))):
    await db.learned_adjustments.delete_many({})
    await _audit(user["email"], "reset", "coach")
    return {"reset": True}


# ---------- QRadar Sync ----------
def _qradar_from_settings(s: dict) -> QRadarClient:
    q = s.get("qradar", {})
    return QRadarClient(
        host=q.get("host", ""), token=q.get("api_token", ""),
        version=q.get("api_version", "12.0"), verify_ssl=q.get("verify_ssl", False),
        domain_id=q.get("domain_id"), processor_id=q.get("processor_id"),
    )


@api.post("/qradar/test")
async def qradar_test(user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER]))):
    s = await db.settings.find_one({"id": "global"}, {"_id": 0}) or {}
    client = _qradar_from_settings(s)
    return client.test_connection()


class QRadarSyncRequest(BaseModel):
    client_id: str
    hours_back: int = 6
    max_offenses: int = 10


@api.post("/qradar/sync")
async def qradar_sync(payload: QRadarSyncRequest,
                      user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER, UserRole.L2, UserRole.L3]))):
    _assert_tenant_access(user, payload.client_id)
    s = await db.settings.find_one({"id": "global"}, {"_id": 0}) or {}
    q = s.get("qradar", {}) or {}
    if not q.get("host") or not q.get("api_token"):
        raise HTTPException(400, "QRadar not configured. Set host and API token in Settings.")
    client = _qradar_from_settings(s)
    time_ms = int((datetime.now(timezone.utc) - timedelta(hours=payload.hours_back)).timestamp() * 1000)
    try:
        offenses_raw = client.fetch_offenses(f"last_updated_time>{time_ms}", limit=payload.max_offenses)
    except Exception as e:
        raise HTTPException(502, f"QRadar fetch failed: {e}")
    saved = 0
    for o in offenses_raw:
        sev = int(o.get("severity", 0))
        sev_label = "Critical" if sev >= 9 else "High" if sev >= 7 else "Medium" if sev >= 4 else "Low"
        try:
            events = client.fetch_events_for_offense(o["id"], max_events=25)
        except Exception:
            events = []
        doc = {
            "id": str(uuid.uuid4()),
            "qradar_offense_id": o.get("id"),
            "client_id": payload.client_id,
            "description": o.get("description", "QRadar offense"),
            "magnitude": o.get("magnitude", 0),
            "credibility": o.get("credibility", 0),
            "severity": sev,
            "relevance": o.get("relevance", 0),
            "severity_label": sev_label,
            "status": "OPEN",
            "assigned_user": o.get("assigned_to"),
            "start_time": datetime.fromtimestamp(o.get("start_time", 0) / 1000, tz=timezone.utc).isoformat() if o.get("start_time") else _now(),
            "last_updated": datetime.fromtimestamp(o.get("last_updated_time", 0) / 1000, tz=timezone.utc).isoformat() if o.get("last_updated_time") else _now(),
            "categories": o.get("categories", []) or [],
            "source_count": o.get("source_count", 0),
            "destination_count": o.get("local_destination_count", 0),
            "username_count": o.get("username_count", 0),
            "event_count": o.get("event_count", 0),
            "flow_count": o.get("flow_count", 0),
            "network": o.get("inactive", ""),
            "domain_id": o.get("domain_id"),
            "offense_type": str(o.get("offense_type", "")),
            "rules": [r.get("name", "") for r in (o.get("rules", []) or [])],
            "source_ips": o.get("source_address_ids", []) or [],
            "destination_ips": o.get("local_destination_address_ids", []) or [],
            "usernames": [],
            "events": events,
            "risk_score": 0,
            "mitre_techniques": [], "iocs": {}, "recommendation": None,
            "confidence": 0, "similar_incidents": [], "kb_matches": [],
            "merged_into": None, "merged_from": [],
            "created_at": _now(),
        }
        # upsert by qradar_offense_id
        existing = await db.offenses.find_one({"qradar_offense_id": doc["qradar_offense_id"],
                                               "client_id": payload.client_id})
        if existing:
            doc["id"] = existing["id"]
            await db.offenses.update_one({"id": existing["id"]}, {"$set": doc})
        else:
            await db.offenses.insert_one(doc)
        saved += 1
    await _audit(user["email"], "qradar_sync", "offenses", None, {"count": saved})
    return {"synced": saved}


# ---------- Settings ----------
@api.get("/settings")
async def get_settings(user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER]))):
    doc = await db.settings.find_one({"id": "global"}, {"_id": 0}) or {}
    # Ensure all sub-objects present with defaults
    defaults = Settings().model_dump()
    for k, v in defaults.items():
        if k == "id":
            continue
        if k not in doc or doc[k] is None:
            doc[k] = v
        elif isinstance(v, dict):
            # merge missing keys within sub-object
            for sk, sv in v.items():
                if sk not in doc[k]:
                    doc[k][sk] = sv
    # redact tokens - show only masked version
    if doc.get("qradar", {}).get("api_token"):
        tok = doc["qradar"]["api_token"]
        doc["qradar"]["api_token_masked"] = "••••" + tok[-4:]
        doc["qradar"]["api_token"] = ""
    for k in ("xsoar", "servicenow", "jira", "freshservice", "slack", "teams", "email"):
        if doc.get(k, {}).get("token"):
            tok = doc[k]["token"]
            doc[k]["token_masked"] = "••••" + tok[-4:]
            doc[k]["token"] = ""
    if doc.get("llm", {}).get("api_token"):
        doc["llm"]["api_token"] = ""
    ti = doc.get("threat_intel", {}) or {}
    for k in ("virustotal_api_key", "abuseipdb_api_key", "misp_api_key"):
        if ti.get(k):
            ti[k + "_masked"] = "••••" + ti[k][-4:]
            ti[k] = ""
    if ti.get("virustotal_api_keys"):
        raw = ti["virustotal_api_keys"]
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        ti["virustotal_api_keys_count"] = len(lines)
        ti["virustotal_api_keys_masked"] = [("••••" + ln[-4:]) if len(ln) > 4 else "••••" for ln in lines]
        ti["virustotal_api_keys"] = ""
    doc["threat_intel"] = ti
    return doc


@api.put("/settings")
async def update_settings(payload: Settings,
                          user: dict = Depends(require_roles([UserRole.ADMIN]))):
    data = payload.model_dump()
    data["id"] = "global"
    data["updated_at"] = _now()
    # Preserve existing tokens when the incoming value is blank (frontend receives redacted)
    existing = await db.settings.find_one({"id": "global"}, {"_id": 0}) or {}
    if not data.get("qradar", {}).get("api_token") and existing.get("qradar", {}).get("api_token"):
        data["qradar"]["api_token"] = existing["qradar"]["api_token"]
    for k in ("xsoar", "servicenow", "jira", "freshservice", "slack", "teams", "email"):
        if not data.get(k, {}).get("token") and existing.get(k, {}).get("token"):
            data[k]["token"] = existing[k]["token"]
    if not data.get("llm", {}).get("api_token") and existing.get("llm", {}).get("api_token"):
        data["llm"]["api_token"] = existing["llm"]["api_token"]
    ti_existing = existing.get("threat_intel", {}) or {}
    ti_new = data.get("threat_intel", {}) or {}
    for k in ("virustotal_api_key", "abuseipdb_api_key", "misp_api_key", "virustotal_api_keys"):
        val = ti_new.get(k)
        if val == "__CLEAR__":
            # Explicit clear request — wipe the stored secret.
            ti_new[k] = ""
        elif not val and ti_existing.get(k):
            # Empty submission = untouched → preserve.
            ti_new[k] = ti_existing[k]
    data["threat_intel"] = ti_new
    await db.settings.update_one({"id": "global"}, {"$set": data}, upsert=True)
    await _audit(user["email"], "update", "settings")
    return {"ok": True}


# ---------- Knowledge Base ----------
@api.get("/kb")
async def list_kb(client_id: str, user: dict = Depends(get_current_user)):
    _assert_tenant_access(user, client_id)
    return await db.kb_entries.find({"client_id": client_id}, {"_id": 0}).sort("uploaded_at", -1).to_list(500)


@api.post("/kb/upload")
async def upload_kb(client_id: str = Form(...), kb_type: str = Form(...),
                    file: UploadFile = File(...),
                    user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER, UserRole.L2, UserRole.L3]))):
    _assert_tenant_access(user, client_id)
    # Read the file contents once (uploads > ~50MB are rejected to protect the pod).
    content = await file.read()
    size = len(content)
    if size > 50 * 1024 * 1024:
        raise HTTPException(413, "File too large (max 50 MB). Split it and upload in parts.")

    # Persist the KB entry immediately with PROCESSING status so the UI can show progress.
    entry = KBEntry(
        client_id=client_id, kb_type=kb_type, filename=file.filename,
        content_summary="(processing...)",
        document_count=0, status="PROCESSING",
        file_size_bytes=size, uploaded_by=user["email"],
    )
    await db.kb_entries.insert_one(entry.model_dump())
    await _audit(user["email"], "upload_start", "kb", entry.id,
                 {"filename": file.filename, "size": size})

    # Fire-and-forget async task so the HTTP response returns IMMEDIATELY
    # (avoids Cloudflare/ingress 100s timeout for large embed batches).
    asyncio.create_task(_ingest_kb_background(entry.id, client_id, kb_type, file.filename, content))
    return entry


def _ingest_kb_sync(client_id: str, kb_type: str, filename: str, content: bytes):
    """CPU-bound work: parse + embed + chroma add. Runs in a thread executor."""
    chunks = kb_ingest.parse_upload(filename, content)
    if len(chunks) > 5000:
        chunks = chunks[:5000]
    added = rag_store.add_documents(client_id, kb_type, filename, chunks)
    summary = kb_ingest.content_summary(chunks)
    return added, summary


async def _ingest_kb_background(entry_id: str, client_id: str, kb_type: str,
                                filename: str, content: bytes):
    """Runs on the event loop; offloads CPU work to a thread pool executor.
    The HTTP response has already been sent by this point."""
    try:
        loop = asyncio.get_event_loop()
        added, summary = await loop.run_in_executor(
            None, _ingest_kb_sync, client_id, kb_type, filename, content
        )
        await db.kb_entries.update_one(
            {"id": entry_id},
            {"$set": {"status": "READY", "document_count": added,
                      "content_summary": summary, "completed_at": _now(), "error": None}},
        )
        logger.info("KB entry %s ingested: %d chunks", entry_id, added)
    except Exception as e:
        logger.exception("KB ingestion failed for %s: %s", entry_id, e)
        await db.kb_entries.update_one(
            {"id": entry_id},
            {"$set": {"status": "FAILED", "error": str(e)[:500], "completed_at": _now()}},
        )


@api.delete("/kb/{entry_id}")
async def delete_kb(entry_id: str,
                    user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER]))):
    doc = await db.kb_entries.find_one({"id": entry_id})
    if not doc:
        raise HTTPException(404, "Not found")
    _assert_tenant_access(user, doc.get("client_id"))
    rag_store.delete_for_client(doc["client_id"], doc["filename"])
    await db.kb_entries.delete_one({"id": entry_id})
    await _audit(user["email"], "delete", "kb", entry_id)
    return {"deleted": True}


@api.get("/kb/status")
async def kb_status(user: dict = Depends(get_current_user)):
    return rag_store.status()


class KBSearchRequest(BaseModel):
    client_id: str
    query: str
    n_results: int = 5


@api.post("/kb/search")
async def kb_search(payload: KBSearchRequest, user: dict = Depends(get_current_user)):
    """Analyst-facing preview: query the vector store directly to verify what will be retrieved.
    Available to every authenticated role so L1s can inspect context before an investigation
    and admins can audit ingestion quality."""
    _assert_tenant_access(user, payload.client_id)
    if not payload.query.strip():
        return {"matches": [], "count": 0}
    matches = rag_store.query(payload.client_id, payload.query, n_results=max(1, min(20, payload.n_results)))
    return {"matches": matches, "count": len(matches), "query": payload.query}


@api.post("/kb/{entry_id}/retry")
async def retry_kb(entry_id: str,
                   user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER]))):
    """Mark a stuck/failed entry so the user can re-upload the file. We don't persist raw
    uploads, so the analyst must upload again — this simply cleans up the placeholder row."""
    doc = await db.kb_entries.find_one({"id": entry_id})
    if not doc:
        raise HTTPException(404, "Not found")
    _assert_tenant_access(user, doc.get("client_id"))
    rag_store.delete_for_client(doc["client_id"], doc["filename"])
    await db.kb_entries.delete_one({"id": entry_id})
    await _audit(user["email"], "retry_delete", "kb", entry_id)
    return {"deleted": True, "message": "Row cleared — please upload the file again."}


# ---------- Tickets ----------
@api.get("/tickets")
async def list_tickets(client_id: Optional[str] = None, status_filter: Optional[str] = None,
                       user: dict = Depends(get_current_user)):
    q = _tenant_filter(user, client_id)
    if status_filter:
        q["status"] = status_filter
    return await db.tickets.find(q, {"_id": 0}).sort("created_at", -1).to_list(500)


@api.post("/tickets")
async def create_ticket(payload: TicketCreate,
                        user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER, UserRole.L1, UserRole.L2, UserRole.L3]))):
    off = await db.offenses.find_one({"id": payload.offense_id}, {"_id": 0})
    if not off:
        raise HTTPException(404, "Offense not found")
    _assert_tenant_access(user, off.get("client_id"))
    analysis = off.get("ai_analysis") or {}
    # Ensure mssp_report exists even if user creates ticket before investigation
    mssp = analysis.get("mssp_report")
    if not mssp:
        try:
            mssp = soc_engine.build_mssp_report(off, similar=off.get("similar_incidents") or [],
                                                iocs=off.get("iocs") or {},
                                                mitre=off.get("mitre_techniques") or [],
                                                risk=int(off.get("risk_score") or 0),
                                                kb_matches=off.get("kb_matches") or [])
            mssp["recommendation_text"] = off.get("recommendation") or "Monitor"
        except Exception:
            mssp = None
    ticket = Ticket(
        client_id=off["client_id"],
        offense_ids=[off["id"]],
        title=f"[{off.get('severity_label') or 'Low'}] {(off.get('description') or '')[:120]}",
        executive_summary=analysis.get("executive_summary") or off.get("description") or "",
        root_cause=analysis.get("attack_stage") or "",
        timeline=analysis.get("timeline") or [],
        affected_assets=(list(off.get("destination_ips") or []) + list(off.get("source_ips") or []))[:10],
        mitre=off.get("mitre_techniques") or [],
        iocs=off.get("iocs") or {},
        evidence="; ".join(off.get("rules") or []) or "N/A",
        recommended_action=off.get("recommendation") or "Monitor",
        risk_score=int(off.get("risk_score") or 0),
        mssp_report=mssp,
        status="PENDING_APPROVAL",
        destination=payload.destination,
        created_by=user["email"],
    )
    await db.tickets.insert_one(ticket.model_dump())
    await db.offenses.update_one({"id": off["id"]}, {"$set": {"status": "PENDING_APPROVAL"}})
    await _audit(user["email"], "create", "ticket", ticket.id, {"offense_id": off["id"]})
    return ticket


@api.post("/tickets/{ticket_id}/approve")
async def approve_ticket(ticket_id: str, payload: TicketApproval,
                         user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER, UserRole.L3]))):
    t = await db.tickets.find_one({"id": ticket_id}, {"_id": 0})
    if not t:
        raise HTTPException(404, "Not found")
    _assert_tenant_access(user, t.get("client_id"))
    if payload.approved:
        # Simulate push to destination
        ref = f"MOCK-{ticket_id[:8].upper()}"
        updates = {"status": "PUSHED", "approver": user["email"], "approved_at": _now(), "external_ref": ref}
    else:
        updates = {"status": "REJECTED", "approver": user["email"], "approved_at": _now()}
    await db.tickets.update_one({"id": ticket_id}, {"$set": updates})
    await _audit(user["email"], "approve" if payload.approved else "reject", "ticket", ticket_id)
    return {**t, **updates}


@api.post("/tickets/merge")
async def merge_tickets(payload: TicketMerge,
                        user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER, UserRole.L2, UserRole.L3]))):
    if len(payload.ticket_ids) < 2:
        raise HTTPException(400, "Provide at least 2 ticket IDs")
    tickets = await db.tickets.find({"id": {"$in": payload.ticket_ids}}, {"_id": 0}).to_list(50)
    if len(tickets) != len(payload.ticket_ids):
        raise HTTPException(404, "Some tickets not found")
    if len({t["client_id"] for t in tickets}) > 1:
        raise HTTPException(400, "Cannot merge tickets from different clients")
    _assert_tenant_access(user, tickets[0]["client_id"])

    merged_offense_ids: list[str] = []
    merged_mitre: list[dict] = []
    merged_iocs: dict = {}
    max_risk = 0
    for t in tickets:
        merged_offense_ids.extend(t.get("offense_ids", []))
        merged_mitre.extend(t.get("mitre", []))
        for k, v in (t.get("iocs") or {}).items():
            if isinstance(v, list):
                merged_iocs.setdefault(k, [])
                merged_iocs[k].extend(v)
        max_risk = max(max_risk, int(t.get("risk_score", 0)))
    # dedupe
    for k, v in merged_iocs.items():
        merged_iocs[k] = sorted(set(v))
    dedup_mitre = {t["technique_id"]: t for t in merged_mitre}.values()

    parent = Ticket(
        client_id=tickets[0]["client_id"],
        offense_ids=list(set(merged_offense_ids)),
        title=payload.title or f"Merged Incident ({len(tickets)} tickets)",
        executive_summary="Merged from " + ", ".join(t["title"] for t in tickets),
        root_cause="Multiple correlated events",
        timeline=[],
        affected_assets=list({a for t in tickets for a in t.get("affected_assets", [])}),
        mitre=list(dedup_mitre),
        iocs=merged_iocs,
        evidence="; ".join({t.get("evidence", "") for t in tickets}),
        recommended_action="Escalate L3",
        risk_score=max_risk,
        status="PENDING_APPROVAL",
        destination=tickets[0].get("destination", "internal"),
        created_by=user["email"],
    )
    await db.tickets.insert_one(parent.model_dump())
    await db.tickets.update_many({"id": {"$in": payload.ticket_ids}},
                                 {"$set": {"status": "MERGED", "merged_into": parent.id}})
    await _audit(user["email"], "merge", "ticket", parent.id, {"source_ids": payload.ticket_ids})
    return parent


# ---------- Audit logs ----------
@api.get("/audit")
async def list_audit(limit: int = 200,
                     user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER]))):
    return await db.audit_logs.find({}, {"_id": 0}).sort("timestamp", -1).to_list(limit)


class MsspReportUpdate(BaseModel):
    # Free-form partial update — analyst can override any field on the MSSP report.
    fields: Optional[dict] = None       # {offense_id, offense_name, severity, ...}
    custom_fields: Optional[List[dict]] = None  # [{"key":"Client SLA","value":"P1 - 15min"}]
    analysis_lines: Optional[List[dict]] = None  # [{n:1,text:"..."}, ...]
    recommendations: Optional[List[str]] = None
    verdict: Optional[str] = None       # TP | FP | Suspicious
    verdict_reason: Optional[str] = None
    analyst_notes: Optional[str] = None


@api.patch("/offenses/{offense_id}/mssp-report")
async def edit_mssp_report(offense_id: str, req: MsspReportUpdate,
                            user: dict = Depends(require_roles(
                                [UserRole.ADMIN, UserRole.SOC_MANAGER, UserRole.L1, UserRole.L2, UserRole.L3]))):
    off = await db.offenses.find_one({"id": offense_id}, {"_id": 0})
    if not off:
        raise HTTPException(404, "Offense not found")
    _assert_tenant_access(user, off.get("client_id"))
    ai = off.get("ai_analysis") or {}
    mssp = ai.get("mssp_report") or {}
    # Merge caller-supplied overrides
    if req.fields:
        # Only allow known top-level string fields to change
        allowed = {"offense_id", "offense_name", "severity", "date_time", "source_ip",
                   "destination_ip", "username", "event_name", "low_level_category",
                   "error_code", "event_id", "failure_reason", "machine_identifier",
                   "log_source"}
        for k, v in req.fields.items():
            if k in allowed:
                mssp[k] = v
    if req.custom_fields is not None:
        # Sanitize free-form key/value additions. Keys become the display label.
        cleaned = []
        seen_keys = set()
        for row in req.custom_fields[:30]:  # cap to prevent abuse
            key = str(row.get("key") or "").strip()[:80]
            value = str(row.get("value") or "").strip()[:1000]
            if not key or key.lower() in seen_keys:
                continue
            seen_keys.add(key.lower())
            cleaned.append({"key": key, "value": value})
        mssp["custom_fields"] = cleaned
    if req.analysis_lines is not None:
        # Sanitize + auto-number
        lines = []
        for i, ln in enumerate(req.analysis_lines, start=1):
            text = str(ln.get("text") or "").strip()
            if text:
                lines.append({"n": i, "text": text[:2000]})
        mssp["analysis_lines"] = lines
    if req.recommendations is not None:
        mssp["recommendations"] = [str(r).strip()[:2000] for r in req.recommendations if str(r).strip()]
    if req.verdict is not None:
        if req.verdict not in ("TP", "FP", "Suspicious", ""):
            raise HTTPException(400, "verdict must be TP | FP | Suspicious")
        mssp["verdict"] = req.verdict or None
    if req.verdict_reason is not None:
        mssp["verdict_reason"] = str(req.verdict_reason).strip()[:2000] or None
    if req.analyst_notes is not None:
        mssp["analyst_notes"] = str(req.analyst_notes).strip()[:5000] or None

    mssp["edited_by"] = user["email"]
    mssp["edited_at"] = _now()
    ai["mssp_report"] = mssp
    await db.offenses.update_one({"id": offense_id},
                                 {"$set": {"ai_analysis": ai, "last_updated": _now()}})
    await _audit(user["email"], "edit", "mssp_report", offense_id,
                 {"has_fields": bool(req.fields),
                  "custom_count": len(mssp.get("custom_fields") or []) if req.custom_fields is not None else None,
                  "has_analysis": req.analysis_lines is not None,
                  "has_recs": req.recommendations is not None,
                  "has_verdict": req.verdict is not None,
                  "has_notes": req.analyst_notes is not None})
    return await db.offenses.find_one({"id": offense_id}, {"_id": 0})


@api.get("/threat-intel/vt-health")
async def vt_health(user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.SOC_MANAGER]))):
    """Snapshot of VirusTotal API-key rotation health."""
    from threat_intel import parse_vt_keys, vt_key_health
    settings_doc = await db.settings.find_one({"id": "global"}, {"_id": 0}) or {}
    ti = settings_doc.get("threat_intel") or {}
    if not ti.get("virustotal_enabled"):
        return {"enabled": False, "total": 0, "healthy": 0, "cooling_off": 0}
    keys = parse_vt_keys(ti.get("virustotal_api_keys", ""), ti.get("virustotal_api_key", ""))
    return {"enabled": True, **vt_key_health(keys)}


# ---------- Health ----------
@api.get("/")
async def root():
    return {"service": "SOCPilot AI", "status": "ok", "time": _now()}


# ---------- register ----------
app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def _shutdown():
    pass
