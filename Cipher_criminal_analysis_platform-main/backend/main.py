import os
import math
import csv
import io
import hashlib
import datetime
from typing import Optional, List, Dict, Any
from collections import deque

from fastapi import (
    FastAPI, Depends, HTTPException, status, UploadFile, File, Form, Query, Request
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, func

from .database import get_db, engine, Base
from .models import (
    User, Case, Document, Entity, Relationship, Location, LocationNode,
    SpatialEvent, ReviewItem, ChainOfCustodyLog
)
from .auth import (
    get_password_hash, verify_password, create_access_token,
    get_current_user, require_active_user, require_roles
)
from .neo4j_service import neo4j_service

# Initialize tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="CIPHER - Criminal Intelligence & Pattern Heuristic Engine",
    description="AI-powered criminal network analysis, geospatial GIS mapping, and case reconstruction backend.",
    version="2.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {".pdf", ".csv", ".txt", ".json", ".docx", ".png", ".jpg", ".jpeg"}
MAX_FILE_SIZE = 50 * 1024 * 1024 # 50 MB
ADMIN_SETUP_SECRET = os.getenv("ADMIN_SETUP_SECRET", "cipher_admin_secret_key_2026")

# ------------------------------------------------------------
# PYDANTIC SCHEMAS
# ------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str
    password: str = Field(..., min_length=6)
    full_name: Optional[str] = None
    role: Optional[str] = "INVESTIGATOR"
    admin_secret: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class CaseCreate(BaseModel):
    title: str
    case_number: str
    description: Optional[str] = None
    status: Optional[str] = "ACTIVE"
    priority: Optional[str] = "HIGH"
    lead_investigator: Optional[str] = None

class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    lead_investigator: Optional[str] = None

class EntityCreate(BaseModel):
    id: Optional[str] = None
    name: str
    type: str = "PERSON"
    role: Optional[str] = None
    confidence: Optional[float] = 1.0
    aliases: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    verification_status: Optional[str] = "verified"
    source_document_id: Optional[int] = None

class RelationshipCreate(BaseModel):
    id: Optional[str] = None
    source_id: str
    target_id: str
    relationship_type: str = "CONNECTED"
    confidence: Optional[float] = 1.0
    evidence_sentence: Optional[str] = None
    status: Optional[str] = "verified"
    source_document_id: Optional[int] = None

class RelationshipReviewRequest(BaseModel):
    action: str # "approve", "reject", "edit"
    review_reason: Optional[str] = None
    relationship_type: Optional[str] = None
    confidence: Optional[float] = None
    evidence_sentence: Optional[str] = None

class LocationCreate(BaseModel):
    name: str
    location_type: Optional[str] = "FACILITY"
    latitude: float
    longitude: float
    address: Optional[str] = None
    accuracy_m: Optional[float] = 10.0
    verification_status: Optional[str] = "verified"
    confidence: Optional[float] = 1.0

class EntityMergeRequest(BaseModel):
    primary_entity_id: str
    secondary_entity_id: str
    merged_name: Optional[str] = None
    merged_role: Optional[str] = None

class PathSearchRequest(BaseModel):
    start_entity_id: str
    end_entity_id: str

def to_iso(dt):
    if dt is None:
        return None
    if hasattr(dt, "isoformat"):
        return dt.isoformat()
    return str(dt)

# ------------------------------------------------------------
# HEALTH & INFO ENDPOINTS
# ------------------------------------------------------------

@app.get("/api/health")
@app.get("/health")
def health_check():
    neo4j_ok = neo4j_service.is_available()
    return {
        "status": "healthy",
        "service": "CIPHER FastAPI Backend",
        "database": "connected",
        "neo4j": "connected" if neo4j_ok else "fallback_mode",
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

# ------------------------------------------------------------
# AUTHENTICATION ENDPOINTS
# ------------------------------------------------------------

@app.post("/auth/register")
@app.post("/api/auth/register")
def register_user(req: RegisterRequest, db: Session = Depends(get_db)):
    # Check if username or email already exists
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username is already registered.")
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email is already registered.")

    # Prevent public users from registering as ADMIN unless authorized
    role = "INVESTIGATOR"
    if req.role and req.role.upper() == "ADMIN":
        if req.admin_secret == ADMIN_SETUP_SECRET:
            role = "ADMIN"
        else:
            raise HTTPException(
                status_code=403,
                detail="Registering with ADMIN role requires valid administrative authorization secret."
            )
    elif req.role and req.role.upper() in ["ANALYST", "INVESTIGATOR"]:
        role = req.role.upper()

    user = User(
        username=req.username,
        email=req.email,
        password_hash=get_password_hash(req.password),
        full_name=req.full_name or req.username,
        role=role
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": user.username or user.email, "role": user.role, "id": user.id})
    return {
        "status": "success",
        "message": "User registered successfully.",
        "token": token,
        "user": {
            "id": user.id,
            "username": user.username or user.email,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role
        }
    }

@app.post("/auth/login")
@app.post("/api/auth/login")
def login_user(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(or_(User.username == req.username, User.email == req.username)).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = create_access_token({"sub": user.username or user.email, "role": user.role, "id": user.id})
    return {
        "status": "success",
        "token": token,
        "user": {
            "id": user.id,
            "username": user.username or user.email,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role
        }
    }

@app.get("/auth/me")
@app.get("/api/auth/me")
def get_current_user_profile(user: User = Depends(require_active_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "created_at": to_iso(user.created_at)
    }

# ------------------------------------------------------------
# CASE MANAGEMENT (CRUD, SEARCH, PAGINATION, ROLE ACCESS)
# ------------------------------------------------------------

def check_case_access(case: Case, user: Optional[User]):
    if not user:
        return # Allow public demo access if not authenticated
    if user.role in ["ADMIN", "ANALYST"]:
        return # Admins and analysts have full access
    if case.user_id and case.user_id != user.id:
        raise HTTPException(
            status_code=403,
            detail="Access forbidden: You do not have permission to access another investigator's case."
        )

@app.post("/cases")
@app.post("/api/cases")
def create_case(
    req: CaseCreate,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user)
):
    if db.query(Case).filter(Case.case_number == req.case_number).first():
        raise HTTPException(status_code=400, detail=f"Case number '{req.case_number}' already exists.")

    new_case = Case(
        title=req.title,
        case_number=req.case_number,
        description=req.description,
        status=req.status or "ACTIVE",
        priority=req.priority or "HIGH",
        lead_investigator=req.lead_investigator or (user.full_name if user else "Lead Agent"),
        user_id=user.id if user else None
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)

    # Sync to Neo4j
    neo4j_service.sync_case(new_case.id, new_case.title, new_case.description)

    return new_case

@app.get("/cases")
@app.get("/api/cases")
def list_cases(
    search: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    priority_filter: Optional[str] = Query(None, alias="priority"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user)
):
    query = db.query(Case)

    # Role permission filter
    if user and user.role == "INVESTIGATOR":
        query = query.filter(or_(Case.user_id == user.id, Case.user_id == None))

    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            or_(
                Case.title.ilike(search_pattern),
                Case.case_number.ilike(search_pattern),
                Case.description.ilike(search_pattern),
                Case.lead_investigator.ilike(search_pattern)
            )
        )
    if status_filter:
        query = query.filter(Case.status == status_filter.upper())
    if priority_filter:
        query = query.filter(Case.priority == priority_filter.upper())

    total = query.count()
    cases = query.order_by(Case.id.asc()).offset((page - 1) * limit).limit(limit).all()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "cases": [
            {
                "id": c.id,
                "title": c.title,
                "case_number": c.case_number,
                "description": c.description,
                "status": c.status,
                "priority": c.priority,
                "lead_investigator": c.lead_investigator,
                "created_at": to_iso(c.created_at)
            }
            for c in cases
        ]
    }

@app.get("/cases/{case_id}")
@app.get("/api/cases/{case_id}")
def get_case(case_id: int, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    c = db.query(Case).filter(Case.id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Case not found.")
    check_case_access(c, user)

    entity_count = db.query(Entity).filter(Entity.case_id == case_id).count()
    rel_count = db.query(Relationship).filter(Relationship.case_id == case_id).count()
    doc_count = db.query(Document).filter(Document.case_id == case_id).count()

    return {
        "id": c.id,
        "title": c.title,
        "case_number": c.case_number,
        "description": c.description,
        "status": c.status,
        "priority": c.priority,
        "lead_investigator": c.lead_investigator,
        "created_at": to_iso(c.created_at),
        "updated_at": to_iso(c.updated_at),
        "statistics": {
            "entities": entity_count,
            "relationships": rel_count,
            "documents": doc_count
        }
    }

@app.put("/cases/{case_id}")
@app.put("/api/cases/{case_id}")
def update_case(
    case_id: int,
    req: CaseUpdate,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user)
):
    c = db.query(Case).filter(Case.id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Case not found.")
    check_case_access(c, user)

    if req.title is not None:
        c.title = req.title
    if req.description is not None:
        c.description = req.description
    if req.status is not None:
        c.status = req.status
    if req.priority is not None:
        c.priority = req.priority
    if req.lead_investigator is not None:
        c.lead_investigator = req.lead_investigator

    c.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(c)

    # Sync update to Neo4j
    neo4j_service.sync_case(c.id, c.title, c.description)

    return c

@app.delete("/cases/{case_id}")
@app.delete("/api/cases/{case_id}")
def delete_case(
    case_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["ADMIN", "ANALYST"]))
):
    c = db.query(Case).filter(Case.id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Case not found.")

    db.delete(c)
    db.commit()
    return {"status": "success", "message": f"Case #{case_id} and all associated records deleted."}

def parse_id(id_val):
    if id_val is None:
        return 0
    clean = str(id_val).replace("rel-", "").replace("ent-", "")
    return int(clean) if clean.isdigit() else 0

# ------------------------------------------------------------
# RELATIONSHIP REVIEW WORKFLOW (Checklist Item 1)
# ------------------------------------------------------------

@app.get("/cases/{case_id}/relationships/pending")
@app.get("/api/cases/{case_id}/relationships/pending")
@app.get("/relationships/pending")
@app.get("/api/relationships/pending")
def list_pending_relationships(
    case_id: Optional[int] = None,
    status_filter: Optional[str] = Query("pending", alias="status"),
    source_entity_id: Optional[str] = None,
    target_entity_id: Optional[str] = None,
    source_document_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Relationship)
    if case_id:
        query = query.filter(Relationship.case_id == case_id)
    if status_filter:
        query = query.filter(func.lower(Relationship.verification_status) == status_filter.lower())
    if source_entity_id:
        src = parse_id(source_entity_id)
        if src:
            query = query.filter(Relationship.source_entity_id == src)
    if target_entity_id:
        tgt = parse_id(target_entity_id)
        if tgt:
            query = query.filter(Relationship.target_entity_id == tgt)
    if source_document_id:
        query = query.filter(Relationship.source_document_id == source_document_id)

    pending = query.order_by(Relationship.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "case_id": r.case_id,
            "source_id": str(r.source_entity_id),
            "target_id": str(r.target_entity_id),
            "relationship_type": r.relationship_type,
            "confidence": r.confidence_score,
            "evidence_sentence": r.evidence_sentence,
            "status": r.verification_status,
            "reviewed_by": r.reviewed_by,
            "reviewed_at": to_iso(r.reviewed_at),
            "review_reason": r.review_reason,
            "source_document_id": r.source_document_id,
            "created_at": to_iso(r.created_at)
        }
        for r in pending
    ]

@app.post("/cases/{case_id}/relationships/{relationship_id}/approve")
@app.post("/api/cases/{case_id}/relationships/{relationship_id}/approve")
def approve_relationship(
    case_id: int,
    relationship_id: str,
    reason: Optional[str] = None,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user)
):
    rel_num = parse_id(relationship_id)
    rel = db.query(Relationship).filter(
        Relationship.case_id == case_id,
        (Relationship.id == rel_num) | (Relationship.id == relationship_id)
    ).first()
    if not rel:
        raise HTTPException(status_code=404, detail="Relationship not found.")

    rel.verification_status = "verified"
    rel.reviewed_by = user.username if user else "Investigator"
    rel.reviewed_at = datetime.datetime.utcnow()
    rel.review_reason = reason or "Approved in intelligence review"
    db.commit()

    # Sync approved relationship to Neo4j
    neo4j_service.sync_relationship(case_id, {
        "id": rel.id,
        "source_id": str(rel.source_entity_id),
        "target_id": str(rel.target_entity_id),
        "relationship_type": rel.relationship_type,
        "confidence": rel.confidence_score,
        "status": "verified",
        "evidence_sentence": rel.evidence_sentence
    })

    return {
        "status": "success",
        "message": f"Relationship {relationship_id} approved and synced to graph.",
        "relationship": {
            "id": rel.id,
            "status": rel.verification_status,
            "reviewed_by": rel.reviewed_by,
            "reviewed_at": to_iso(rel.reviewed_at)
        }
    }

@app.post("/cases/{case_id}/relationships/{relationship_id}/reject")
@app.post("/api/cases/{case_id}/relationships/{relationship_id}/reject")
def reject_relationship(
    case_id: int,
    relationship_id: str,
    reason: Optional[str] = None,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user)
):
    rel_num = parse_id(relationship_id)
    rel = db.query(Relationship).filter(
        Relationship.case_id == case_id,
        (Relationship.id == rel_num) | (Relationship.id == relationship_id)
    ).first()
    if not rel:
        raise HTTPException(status_code=404, detail="Relationship not found.")

    rel.verification_status = "rejected"
    rel.reviewed_by = user.username if user else "Investigator"
    rel.reviewed_at = datetime.datetime.utcnow()
    rel.review_reason = reason or "Rejected during intelligence review"
    db.commit()

    # Delete from Neo4j if it was present
    neo4j_service.delete_relationship(case_id, rel.id)

    return {
        "status": "success",
        "message": f"Relationship {relationship_id} rejected.",
        "relationship": {
            "id": rel.id,
            "status": rel.verification_status,
            "reviewed_by": rel.reviewed_by,
            "reviewed_at": to_iso(rel.reviewed_at),
            "reason": rel.review_reason
        }
    }

@app.post("/relationships/{relationship_id}/review")
@app.post("/api/relationships/{relationship_id}/review")
@app.post("/cases/{case_id}/relationships/{relationship_id}/review")
@app.post("/api/cases/{case_id}/relationships/{relationship_id}/review")
def review_relationship(
    relationship_id: str,
    req: RelationshipReviewRequest,
    case_id: Optional[int] = None,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user)
):
    rel_num = parse_id(relationship_id)
    query = db.query(Relationship).filter((Relationship.id == rel_num) | (Relationship.id == relationship_id))
    if case_id:
        query = query.filter(Relationship.case_id == case_id)
    rel = query.first()
    if not rel:
        raise HTTPException(status_code=404, detail="Relationship not found.")

    action = req.action.lower()
    if action == "approve":
        rel.verification_status = "verified"
    elif action == "reject":
        rel.verification_status = "rejected"
    elif action == "edit":
        if req.relationship_type:
            rel.relationship_type = req.relationship_type
        if req.confidence is not None:
            rel.confidence_score = req.confidence
        if req.evidence_sentence is not None:
            rel.evidence_sentence = req.evidence_sentence
    else:
        raise HTTPException(status_code=400, detail="Invalid action. Must be 'approve', 'reject', or 'edit'.")

    rel.reviewed_by = user.username if user else "Investigator"
    rel.reviewed_at = datetime.datetime.utcnow()
    rel.review_reason = req.review_reason or f"Action: {action}"
    db.commit()

    # Update Neo4j
    if rel.verification_status == "verified":
        neo4j_service.sync_relationship(rel.case_id, {
            "id": rel.id,
            "source_id": str(rel.source_entity_id),
            "target_id": str(rel.target_entity_id),
            "relationship_type": rel.relationship_type,
            "confidence": rel.confidence_score,
            "status": "verified",
            "evidence_sentence": rel.evidence_sentence
        })
    else:
        neo4j_service.delete_relationship(rel.case_id, rel.id)

    return {
        "status": "success",
        "action": action,
        "relationship_id": rel.id,
        "new_status": rel.verification_status,
        "reviewed_by": rel.reviewed_by
    }

# ------------------------------------------------------------
# ENTITY MANAGEMENT & DEDUPLICATION (Checklist Item 4)
# ------------------------------------------------------------

@app.get("/cases/{case_id}/entities")
@app.get("/api/cases/{case_id}/entities")
def list_entities(case_id: int, type: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Entity).filter(Entity.case_id == case_id)
    if type:
        query = query.filter(Entity.type == type.upper())
    entities = query.all()
    return [
        {
            "id": e.id,
            "case_id": e.case_id,
            "name": e.name,
            "type": e.type,
            "role": e.role,
            "confidence": e.confidence,
            "aliases": e.aliases,
            "latitude": e.latitude,
            "longitude": e.longitude,
            "verification_status": e.verification_status,
            "source_document_id": e.source_document_id
        }
        for e in entities
    ]

@app.post("/cases/{case_id}/entities")
@app.post("/api/cases/{case_id}/entities")
def create_entity(case_id: int, req: EntityCreate, db: Session = Depends(get_db)):
    # Generate ID if not provided
    entity_id = req.id or f"ent-{int(datetime.datetime.utcnow().timestamp() * 1000)}"

    entity = Entity(
        id=entity_id,
        case_id=case_id,
        name=req.name,
        type=req.type.upper(),
        role=req.role or req.type,
        confidence=req.confidence if req.confidence is not None else 1.0,
        aliases=req.aliases,
        latitude=req.latitude,
        longitude=req.longitude,
        verification_status=req.verification_status or "verified",
        source_document_id=req.source_document_id
    )
    db.add(entity)

    # If coordinates provided, add to Location
    if req.latitude and req.longitude:
        loc = Location(
            case_id=case_id,
            name=req.name,
            location_type=req.type.upper(),
            latitude=req.latitude,
            longitude=req.longitude,
            address="Geo-tagged Entity",
            verification_status="verified"
        )
        db.add(loc)

    db.commit()

    # Sync to Neo4j
    neo4j_service.sync_entity(case_id, {
        "id": entity.id,
        "name": entity.name,
        "type": entity.type,
        "role": entity.role,
        "confidence": entity.confidence,
        "latitude": entity.latitude,
        "longitude": entity.longitude,
        "verification_status": entity.verification_status
    })

    return entity

@app.delete("/cases/{case_id}/entities/{entity_id}")
@app.delete("/api/cases/{case_id}/entities/{entity_id}")
def delete_entity(case_id: int, entity_id: str, db: Session = Depends(get_db)):
    ent = db.query(Entity).filter(Entity.case_id == case_id, Entity.id == str(entity_id)).first()
    if not ent:
        raise HTTPException(status_code=404, detail="Entity not found.")

    # Remove linked relationships
    db.query(Relationship).filter(
        Relationship.case_id == case_id,
        or_(Relationship.source_id == str(entity_id), Relationship.target_id == str(entity_id))
    ).delete(synchronize_session=False)

    db.delete(ent)
    db.commit()

    # Delete from Neo4j
    neo4j_service.delete_entity(case_id, entity_id)

    return {"status": "success", "message": f"Entity {entity_id} and associated relationships deleted."}

@app.get("/cases/{case_id}/entities/duplicates")
@app.get("/api/cases/{case_id}/entities/duplicates")
def detect_duplicate_entities(case_id: int, db: Session = Depends(get_db)):
    entities = db.query(Entity).filter(Entity.case_id == case_id).all()
    duplicates = []

    for i in range(len(entities)):
        for j in range(i + 1, len(entities)):
            e1 = entities[i]
            e2 = entities[j]

            # Compare names and aliases (case insensitive)
            name1 = e1.name.lower().strip()
            name2 = e2.name.lower().strip()

            is_match = False
            match_reason = ""

            if name1 == name2:
                is_match = True
                match_reason = "Exact name match"
            elif (name1 in name2 or name2 in name1) and min(len(name1), len(name2)) > 5:
                is_match = True
                match_reason = "Sub-string name match"
            elif e1.aliases and e2.aliases:
                a1 = {a.strip().lower() for a in e1.aliases.split(",") if a.strip()}
                a2 = {a.strip().lower() for a in e2.aliases.split(",") if a.strip()}
                if a1.intersection(a2):
                    is_match = True
                    match_reason = f"Shared alias: {', '.join(a1.intersection(a2))}"

            if is_match:
                duplicates.append({
                    "entity_a": {"id": e1.id, "name": e1.name, "type": e1.type},
                    "entity_b": {"id": e2.id, "name": e2.name, "type": e2.type},
                    "reason": match_reason
                })

    return {"count": len(duplicates), "potential_duplicates": duplicates}

@app.post("/cases/{case_id}/entities/merge")
@app.post("/api/cases/{case_id}/entities/merge")
def merge_entities(case_id: int, req: EntityMergeRequest, db: Session = Depends(get_db)):
    p_id = str(req.primary_entity_id)
    s_id = str(req.secondary_entity_id)

    if p_id == s_id:
        raise HTTPException(status_code=400, detail="Cannot merge an entity into itself.")

    primary = db.query(Entity).filter(Entity.case_id == case_id, Entity.id == p_id).first()
    secondary = db.query(Entity).filter(Entity.case_id == case_id, Entity.id == s_id).first()

    if not primary or not secondary:
        raise HTTPException(status_code=404, detail="Primary or secondary entity not found.")

    # Re-wire relationships pointing to/from secondary entity to primary
    relationships = db.query(Relationship).filter(
        Relationship.case_id == case_id,
        or_(Relationship.source_id == s_id, Relationship.target_id == s_id)
    ).all()

    for r in relationships:
        if r.source_id == s_id:
            r.source_id = p_id
        if r.target_id == s_id:
            r.target_id = p_id

    # Combine aliases
    existing_aliases = set([a.strip() for a in (primary.aliases or "").split(",") if a.strip()])
    existing_aliases.add(secondary.name)
    if secondary.aliases:
        existing_aliases.update([a.strip() for a in secondary.aliases.split(",") if a.strip()])
    primary.aliases = ", ".join(existing_aliases)

    if req.merged_name:
        primary.name = req.merged_name
    if req.merged_role:
        primary.role = req.merged_role

    # Delete secondary entity
    db.delete(secondary)
    db.commit()

    # Sync to Neo4j
    neo4j_service.delete_entity(case_id, s_id)
    neo4j_service.sync_entity(case_id, {
        "id": primary.id,
        "name": primary.name,
        "type": primary.type,
        "role": primary.role,
        "aliases": primary.aliases
    })

    return {
        "status": "success",
        "message": f"Successfully merged entity {s_id} into {p_id}.",
        "primary_entity": {
            "id": primary.id,
            "name": primary.name,
            "aliases": primary.aliases
        }
    }

# ------------------------------------------------------------
# RELATIONSHIP MANAGEMENT
# ------------------------------------------------------------

@app.get("/cases/{case_id}/relationships")
@app.get("/api/cases/{case_id}/relationships")
def list_relationships(case_id: int, status_filter: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Relationship).filter(Relationship.case_id == case_id)
    if status_filter:
        query = query.filter(Relationship.status == status_filter.lower())
    rels = query.all()
    return [
        {
            "id": r.id,
            "case_id": r.case_id,
            "source_id": r.source_id,
            "target_id": r.target_id,
            "relationship_type": r.relationship_type,
            "confidence": r.confidence,
            "evidence_sentence": r.evidence_sentence,
            "status": r.status,
            "reviewed_by": r.reviewed_by,
            "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None
        }
        for r in rels
    ]

@app.post("/cases/{case_id}/relationships")
@app.post("/api/cases/{case_id}/relationships")
def create_relationship(case_id: int, req: RelationshipCreate, db: Session = Depends(get_db)):
    rel_id = req.id or f"rel-{int(datetime.datetime.utcnow().timestamp() * 1000)}"

    # Ensure source and target entities exist
    src = db.query(Entity).filter(Entity.case_id == case_id, Entity.id == str(req.source_id)).first()
    tgt = db.query(Entity).filter(Entity.case_id == case_id, Entity.id == str(req.target_id)).first()
    if not src or not tgt:
        raise HTTPException(status_code=400, detail="Source or target entity does not exist in this case.")

    rel = Relationship(
        id=rel_id,
        case_id=case_id,
        source_id=str(req.source_id),
        target_id=str(req.target_id),
        relationship_type=req.relationship_type.upper(),
        confidence=req.confidence if req.confidence is not None else 1.0,
        evidence_sentence=req.evidence_sentence,
        status=req.status or "verified",
        source_document_id=req.source_document_id
    )
    db.add(rel)
    db.commit()

    if rel.status == "verified":
        neo4j_service.sync_relationship(case_id, {
            "id": rel.id,
            "source_id": rel.source_id,
            "target_id": rel.target_id,
            "relationship_type": rel.relationship_type,
            "confidence": rel.confidence,
            "status": rel.status,
            "evidence_sentence": rel.evidence_sentence
        })

    return rel

@app.delete("/cases/{case_id}/relationships/{relationship_id}")
@app.delete("/api/cases/{case_id}/relationships/{relationship_id}")
def delete_relationship_endpoint(case_id: int, relationship_id: str, db: Session = Depends(get_db)):
    rel = db.query(Relationship).filter(
        Relationship.case_id == case_id,
        Relationship.id == str(relationship_id)
    ).first()
    if not rel:
        raise HTTPException(status_code=404, detail="Relationship not found.")

    db.delete(rel)
    db.commit()

    neo4j_service.delete_relationship(case_id, relationship_id)
    return {"status": "success", "message": f"Relationship {relationship_id} deleted."}

# ------------------------------------------------------------
# GRAPH DATA & ALGORITHMS (Checklist Item 2)
# ------------------------------------------------------------

@app.get("/cases/{case_id}/graph")
@app.get("/api/cases/{case_id}/graph")
def get_case_graph(case_id: int, db: Session = Depends(get_db)):
    # Try Neo4j first
    neo4j_subgraph = neo4j_service.get_case_subgraph(case_id)
    if neo4j_subgraph and len(neo4j_subgraph.get("nodes", [])) > 0:
        return neo4j_subgraph

    # Fallback to Relational / SQLite DB
    entities = db.query(Entity).filter(Entity.case_id == case_id).all()
    relationships = db.query(Relationship).filter(
        Relationship.case_id == case_id,
        Relationship.status == "verified"
    ).all()

    valid_entity_ids = {e.id for e in entities}

    nodes = [
        {
            "id": e.id,
            "name": e.name,
            "type": e.type,
            "role": e.role or e.type,
            "confidence": e.confidence or 1.0,
            "latitude": e.latitude,
            "longitude": e.longitude,
            "verification_status": e.verification_status
        }
        for e in entities
    ]

    edges = [
        {
            "id": r.id,
            "source": r.source_id,
            "target": r.target_id,
            "type": r.relationship_type,
            "confidence": r.confidence,
            "evidence": r.evidence_sentence or ""
        }
        for r in relationships
        if r.source_id in valid_entity_ids and r.target_id in valid_entity_ids
    ]

    return {"nodes": nodes, "edges": edges}

@app.post("/cases/{case_id}/graph/path")
@app.post("/api/cases/{case_id}/graph/path")
def find_graph_path(case_id: int, req: PathSearchRequest, db: Session = Depends(get_db)):
    start_id = str(req.start_entity_id)
    end_id = str(req.end_entity_id)

    # 1. Try Neo4j pathfinding
    neo4j_path = neo4j_service.find_shortest_path(case_id, start_id, end_id)
    if neo4j_path is not None:
        return neo4j_path

    # 2. Relational BFS Fallback
    relationships = db.query(Relationship).filter(
        Relationship.case_id == case_id,
        Relationship.status == "verified"
    ).all()

    adj: Dict[str, List[tuple]] = {}
    for r in relationships:
        adj.setdefault(r.source_id, []).append((r.target_id, r.id))
        adj.setdefault(r.target_id, []).append((r.source_id, r.id))

    if start_id not in adj or end_id not in adj:
        return {"found": False, "hops": 0, "node_ids": [], "edge_ids": []}

    queue = deque([(start_id, [start_id], [])])
    visited = {start_id}

    while queue:
        curr, path_nodes, path_edges = queue.popleft()
        if curr == end_id:
            node_entities = db.query(Entity).filter(Entity.id.in_(path_nodes)).all()
            name_map = {e.id: e.name for e in node_entities}
            return {
                "found": True,
                "hops": len(path_edges),
                "node_ids": path_nodes,
                "node_names": [name_map.get(nid, nid) for nid in path_nodes],
                "edge_ids": path_edges
            }

        for neighbor, edge_id in adj.get(curr, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path_nodes + [neighbor], path_edges + [edge_id]))

    return {"found": False, "hops": 0, "node_ids": [], "edge_ids": []}

@app.post("/cases/{case_id}/graph/analytics/centrality")
@app.post("/api/cases/{case_id}/graph/analytics/centrality")
def calculate_graph_centrality(case_id: int, db: Session = Depends(get_db)):
    entities = db.query(Entity).filter(Entity.case_id == case_id).all()
    relationships = db.query(Relationship).filter(
        Relationship.case_id == case_id,
        Relationship.status == "verified"
    ).all()

    degrees = {e.id: 0 for e in entities}
    for r in relationships:
        if r.source_id in degrees:
            degrees[r.source_id] += 1
        if r.target_id in degrees:
            degrees[r.target_id] += 1

    max_deg = max(degrees.values()) if degrees and max(degrees.values()) > 0 else 1
    rankings = [
        {
            "id": e.id,
            "name": e.name,
            "degree": degrees[e.id],
            "normalized_centrality": round(degrees[e.id] / max_deg, 3)
        }
        for e in entities
    ]
    rankings.sort(key=lambda x: x["degree"], reverse=True)

    return {
        "disclaimer": "COMPUTED ANALYTIC - NOT AN AI CONCLUSION",
        "rankings": rankings
    }

@app.post("/cases/{case_id}/graph/analytics/communities")
@app.post("/api/cases/{case_id}/graph/analytics/communities")
def detect_communities(case_id: int, db: Session = Depends(get_db)):
    entities = db.query(Entity).filter(Entity.case_id == case_id).all()
    relationships = db.query(Relationship).filter(
        Relationship.case_id == case_id,
        Relationship.status == "verified"
    ).all()

    # Simple Connected Component Graph Partitioning
    parent = {e.id: e.id for e in entities}
    def find(i):
        if parent[i] == i:
            return i
        parent[i] = find(parent[i])
        return parent[i]

    def union(i, j):
        root_i = find(i)
        root_j = find(j)
        if root_i != root_j:
            parent[root_i] = root_j

    for r in relationships:
        if r.source_id in parent and r.target_id in parent:
            union(r.source_id, r.target_id)

    clusters: Dict[str, List[str]] = {}
    for e in entities:
        root = find(e.id)
        clusters.setdefault(root, []).append(e.id)

    color_palette = ["#00e5ff", "#ffb020", "#a855f7", "#10b981", "#f43f5e", "#eab308"]
    result = []
    for idx, (root, node_ids) in enumerate(clusters.items()):
        result.append({
            "community_id": idx + 1,
            "color": color_palette[idx % len(color_palette)],
            "node_ids": node_ids,
            "size": len(node_ids)
        })

    return {"communities": result}

# ------------------------------------------------------------
# GIS & LOCATION ANALYSIS (Checklist Item 3)
# ------------------------------------------------------------

def validate_coordinates(lat: float, lng: float):
    if not (-90.0 <= lat <= 90.0):
        raise HTTPException(status_code=400, detail=f"Invalid latitude {lat}. Must be between -90 and 90.")
    if not (-180.0 <= lng <= 180.0):
        raise HTTPException(status_code=400, detail=f"Invalid longitude {lng}. Must be between -180 and 180.")

@app.get("/cases/{case_id}/locations")
@app.get("/api/cases/{case_id}/locations")
def list_locations(case_id: int, db: Session = Depends(get_db)):
    locs = db.query(Location).filter(Location.case_id == case_id).all()
    return [
        {
            "id": l.id,
            "name": l.name,
            "location_type": l.location_type,
            "latitude": l.latitude,
            "longitude": l.longitude,
            "address": l.address,
            "accuracy_m": l.accuracy_m,
            "verification_status": l.verification_status,
            "confidence": l.confidence
        }
        for l in locs
    ]

@app.post("/cases/{case_id}/locations")
@app.post("/api/cases/{case_id}/locations")
@app.post("/cases/{case_id}/gis/waypoints")
@app.post("/api/cases/{case_id}/gis/waypoints")
def create_location(case_id: int, req: LocationCreate, db: Session = Depends(get_db)):
    validate_coordinates(req.latitude, req.longitude)

    loc = Location(
        case_id=case_id,
        name=req.name,
        location_type=req.location_type or "FACILITY",
        latitude=req.latitude,
        longitude=req.longitude,
        address=req.address or "Plotted Waypoint",
        accuracy_m=req.accuracy_m or 10.0,
        verification_status=req.verification_status or "verified",
        confidence=req.confidence or 1.0
    )
    db.add(loc)

    loc_node = LocationNode(
        case_id=case_id,
        name=req.name,
        label=req.name,
        latitude=req.latitude,
        longitude=req.longitude,
        node_type=req.location_type or "POINT",
        risk_level="MEDIUM"
    )
    db.add(loc_node)
    db.commit()
    db.refresh(loc)

    return loc

@app.get("/cases/{case_id}/gis-data")
@app.get("/api/cases/{case_id}/gis-data")
@app.get("/cases/{case_id}/locations/geojson")
@app.get("/api/cases/{case_id}/locations/geojson")
def get_gis_geojson(case_id: int, db: Session = Depends(get_db)):
    # Fetch locations from locations table and entities with lat/lng
    locations = db.query(Location).filter(Location.case_id == case_id).all()
    entities = db.query(Entity).filter(
        Entity.case_id == case_id,
        Entity.latitude.isnot(None),
        Entity.longitude.isnot(None)
    ).all()

    features = []
    seen_coords = set()

    for l in locations:
        key = (round(l.latitude, 5), round(l.longitude, 5))
        seen_coords.add(key)
        features.append({
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [l.longitude, l.latitude]
            },
            "properties": {
                "id": l.id,
                "name": l.name,
                "type": l.location_type,
                "address": l.address,
                "confidence": l.confidence,
                "verification_status": l.verification_status
            }
        })

    for e in entities:
        key = (round(e.latitude, 5), round(e.longitude, 5))
        if key not in seen_coords:
            seen_coords.add(key)
            features.append({
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    "coordinates": [e.longitude, e.latitude]
                },
                "properties": {
                    "id": e.id,
                    "name": e.name,
                    "type": e.type,
                    "role": e.role,
                    "confidence": e.confidence,
                    "verification_status": e.verification_status
                }
            })

    return {
        "type": "FeatureCollection",
        "features": features
    }

@app.get("/cases/{case_id}/gis/nearby")
@app.get("/api/cases/{case_id}/gis/nearby")
def find_nearby_locations(
    case_id: int,
    latitude: float = Query(...),
    longitude: float = Query(...),
    radius_meters: float = Query(5000.0, ge=10.0, le=1000000.0),
    db: Session = Depends(get_db)
):
    validate_coordinates(latitude, longitude)
    locations = db.query(Location).filter(Location.case_id == case_id).all()
    entities = db.query(Entity).filter(
        Entity.case_id == case_id,
        Entity.latitude.isnot(None),
        Entity.longitude.isnot(None)
    ).all()

    # Haversine formula
    R = 6371000 # Earth radius in meters
    phi1 = math.radians(latitude)

    matches = []
    all_points = [(l.name, l.location_type, l.latitude, l.longitude, "location", l.id) for l in locations] + \
                 [(e.name, e.type, e.latitude, e.longitude, "entity", e.id) for e in entities]

    for name, p_type, lat, lng, kind, p_id in all_points:
        phi2 = math.radians(lat)
        delta_phi = math.radians(lat - latitude)
        delta_lambda = math.radians(lng - longitude)

        a = math.sin(delta_phi / 2.0) ** 2 + \
            math.cos(phi1) * math.cos(phi2) * (math.sin(delta_lambda / 2.0) ** 2)
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        d = R * c

        if d <= radius_meters:
            matches.append({
                "id": p_id,
                "name": name,
                "type": p_type,
                "kind": kind,
                "latitude": lat,
                "longitude": lng,
                "distance_meters": round(d, 1)
            })

    matches.sort(key=lambda x: x["distance_meters"])
    return {
        "center": {"latitude": latitude, "longitude": longitude},
        "radius_meters": radius_meters,
        "count": len(matches),
        "results": matches
    }

@app.get("/cases/{case_id}/gis/corridors")
@app.get("/api/cases/{case_id}/gis/corridors")
def get_gis_corridors(case_id: int, db: Session = Depends(get_db)):
    entities = {
        e.id: e for e in db.query(Entity).filter(
            Entity.case_id == case_id,
            Entity.latitude.isnot(None),
            Entity.longitude.isnot(None)
        ).all()
    }
    relationships = db.query(Relationship).filter(
        Relationship.case_id == case_id,
        Relationship.status == "verified"
    ).all()

    corridors = []
    for r in relationships:
        src = entities.get(r.source_id)
        tgt = entities.get(r.target_id)
        if src and tgt and (src.latitude != tgt.latitude or src.longitude != tgt.longitude):
            corridors.append({
                "id": f"corridor-{r.id}",
                "relationship_id": r.id,
                "type": r.relationship_type,
                "evidence": r.evidence_sentence or "",
                "start": {"id": src.id, "name": src.name, "coords": [src.latitude, src.longitude]},
                "end": {"id": tgt.id, "name": tgt.name, "coords": [tgt.latitude, tgt.longitude]}
            })

    return {"corridors": corridors}

# ------------------------------------------------------------
# DOCUMENT INGESTION & CSV BULK IMPORT (Checklist Item 4)
# ------------------------------------------------------------

@app.post("/cases/{case_id}/documents")
@app.post("/api/cases/{case_id}/documents")
async def upload_document(
    case_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user)
):
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"File extension '{ext}' is not supported. Allowed formats: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    content = await file.read()
    file_size = len(content)
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File size ({round(file_size / (1024*1024), 2)} MB) exceeds 50MB limit."
        )

    # Calculate SHA256 Hash
    sha256 = hashlib.sha256(content).hexdigest()
    timestamp_str = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    safe_filename = f"{timestamp_str}_{os.path.basename(file.filename)}"
    save_path = os.path.join(UPLOAD_DIR, safe_filename)

    with open(save_path, "wb") as f:
        f.write(content)

    doc = Document(
        case_id=case_id,
        filename=file.filename,
        file_path=save_path,
        file_type=ext.replace(".", "").upper(),
        file_size=file_size,
        status="COMPLETED",
        sha256_hash=sha256,
        uploader_id=user.id if user else None
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    # Log to Chain of Custody
    last_log = db.query(ChainOfCustodyLog).filter(ChainOfCustodyLog.case_id == case_id).order_by(ChainOfCustodyLog.id.desc()).first()
    prev_hash = last_log.hash_value if last_log else "0" * 64

    custody_entry = ChainOfCustodyLog(
        case_id=case_id,
        document_id=doc.id,
        action="DOCUMENT_UPLOADED",
        performed_by=user.username if user else "Investigator",
        hash_value=sha256,
        previous_hash=prev_hash,
        details=f"Uploaded evidence file: {file.filename} ({file_size} bytes, SHA-256: {sha256[:16]}...)"
    )
    db.add(custody_entry)
    db.commit()

    return {
        "status": "success",
        "document_id": doc.id,
        "filename": doc.filename,
        "sha256": sha256,
        "size_bytes": file_size
    }

@app.post("/cases/{case_id}/import-csv")
@app.post("/api/cases/{case_id}/import-csv")
async def import_csv_data(
    case_id: int,
    request: Request,
    file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user)
):
    csv_text = ""
    if file:
        content = await file.read()
        csv_text = content.decode("utf-8", errors="ignore")
    else:
        # Check JSON or plain body
        body = await request.body()
        csv_text = body.decode("utf-8", errors="ignore")
        if request.headers.get("content-type", "").startswith("application/json"):
            try:
                data = await request.json()
                csv_text = data.get("csv", "") or data.get("content", "")
            except Exception:
                pass

    if not csv_text.strip():
        raise HTTPException(status_code=400, detail="No CSV content provided.")

    # Auto-detect delimiter
    first_line = csv_text.strip().split("\n")[0]
    delimiter = ","
    if "\t" in first_line:
        delimiter = "\t"
    elif ";" in first_line:
        delimiter = ";"

    reader = csv.DictReader(io.StringIO(csv_text), delimiter=delimiter)
    headers = [h.strip().lower() for h in (reader.fieldnames or [])]

    entities_created = 0
    relationships_created = 0

    existing_entities = {e.name.lower(): e.id for e in db.query(Entity).filter(Entity.case_id == case_id).all()}

    for row in reader:
        # Clean keys
        clean_row = {k.strip().lower(): v.strip() for k, v in row.items() if k and v}

        # Check for source/target relationship schema
        src_name = clean_row.get("source") or clean_row.get("from") or clean_row.get("caller") or clean_row.get("sender")
        tgt_name = clean_row.get("target") or clean_row.get("to") or clean_row.get("receiver") or clean_row.get("connected_to")
        rel_type = clean_row.get("relationship") or clean_row.get("type") or clean_row.get("link") or "CONNECTED"
        evidence = clean_row.get("evidence") or clean_row.get("sentence") or clean_row.get("notes") or ""

        # Or Entity Schema (name, type, role, latitude, longitude)
        name = clean_row.get("name") or clean_row.get("label") or clean_row.get("entity")

        if src_name and tgt_name:
            # Resolve or create source entity
            src_id = existing_entities.get(src_name.lower())
            if not src_id:
                src_id = f"ent-{int(datetime.datetime.utcnow().timestamp() * 1000)}-{entities_created}"
                src_ent = Entity(id=src_id, case_id=case_id, name=src_name, type="PERSON", verification_status="verified")
                db.add(src_ent)
                existing_entities[src_name.lower()] = src_id
                entities_created += 1

            # Resolve or create target entity
            tgt_id = existing_entities.get(tgt_name.lower())
            if not tgt_id:
                tgt_id = f"ent-{int(datetime.datetime.utcnow().timestamp() * 1000)}-{entities_created + 1}"
                tgt_ent = Entity(id=tgt_id, case_id=case_id, name=tgt_name, type="PERSON", verification_status="verified")
                db.add(tgt_ent)
                existing_entities[tgt_name.lower()] = tgt_id
                entities_created += 1

            # Create Relationship
            rel_id = f"rel-{int(datetime.datetime.utcnow().timestamp() * 1000)}-{relationships_created}"
            rel = Relationship(
                id=rel_id,
                case_id=case_id,
                source_id=src_id,
                target_id=tgt_id,
                relationship_type=rel_type.upper(),
                evidence_sentence=evidence,
                status="verified"
            )
            db.add(rel)
            relationships_created += 1

        elif name:
            if name.lower() not in existing_entities:
                ent_id = f"ent-{int(datetime.datetime.utcnow().timestamp() * 1000)}-{entities_created}"
                ent_type = (clean_row.get("type") or "PERSON").upper()
                role = clean_row.get("role") or ent_type
                lat = float(clean_row["latitude"]) if "latitude" in clean_row and clean_row["latitude"] else None
                lng = float(clean_row["longitude"]) if "longitude" in clean_row and clean_row["longitude"] else None

                ent = Entity(
                    id=ent_id,
                    case_id=case_id,
                    name=name,
                    type=ent_type,
                    role=role,
                    latitude=lat,
                    longitude=lng,
                    verification_status="verified"
                )
                db.add(ent)
                existing_entities[name.lower()] = ent_id
                entities_created += 1

    db.commit()

    return {
        "status": "success",
        "message": f"Successfully imported {entities_created} entities and {relationships_created} relationships.",
        "entities_created": entities_created,
        "relationships_created": relationships_created
    }

# ------------------------------------------------------------
# CHAIN OF CUSTODY (Evidence Integrity)
# ------------------------------------------------------------

@app.get("/cases/{case_id}/chain-of-custody")
@app.get("/api/cases/{case_id}/chain-of-custody")
def get_chain_of_custody(case_id: int, db: Session = Depends(get_db)):
    logs = db.query(ChainOfCustodyLog).filter(ChainOfCustodyLog.case_id == case_id).order_by(ChainOfCustodyLog.timestamp.asc()).all()
    return [
        {
            "id": l.id,
            "case_id": l.case_id,
            "document_id": l.document_id,
            "action": l.action,
            "performed_by": l.performed_by,
            "hash_value": l.hash_value,
            "previous_hash": l.previous_hash,
            "timestamp": l.timestamp.isoformat(),
            "details": l.details
        }
        for l in logs
    ]
