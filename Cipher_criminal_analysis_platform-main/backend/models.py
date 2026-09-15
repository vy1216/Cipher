from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Float
from sqlalchemy.sql import func

from database import Base


# ============================================================
# USER MODEL
# ============================================================

class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    full_name = Column(
        String(100),
        nullable=False
    )

    email = Column(
        String(150),
        unique=True,
        nullable=False,
        index=True
    )

    password_hash = Column(
        String(255),
        nullable=False
    )

    role = Column(
        String(30),
        nullable=False,
        default="INVESTIGATOR"
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )


# ============================================================
# CASE MODEL
# ============================================================

class Case(Base):
    __tablename__ = "cases"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    case_number = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True
    )

    title = Column(
        String(200),
        nullable=False
    )

    description = Column(
        Text,
        nullable=True
    )

    status = Column(
        String(30),
        nullable=False,
        default="OPEN"
    )

    priority = Column(
        String(20),
        nullable=False,
        default="MEDIUM"
    )

    created_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )


# ============================================================
# DOCUMENT MODEL
# ============================================================

class Document(Base):
    __tablename__ = "documents"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    case_id = Column(
        Integer,
        ForeignKey("cases.id"),
        nullable=False,
        index=True
    )

    filename = Column(
        String(255),
        nullable=False
    )

    file_type = Column(
        String(100),
        nullable=False
    )

    file_path = Column(
        String(500),
        nullable=False
    )

    processing_status = Column(
        String(30),
        nullable=False,
        default="UPLOADED"
    )

    error_message = Column(
        Text,
        nullable=True
    )

    file_size_bytes = Column(
        Integer,
        nullable=True
    )

    mime_type = Column(
        String(100),
        nullable=True
    )

    uploaded_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False
    )

    uploaded_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )


# ============================================================
# LOCATION NODE MODEL (GIS)
# ============================================================

class LocationNode(Base):
    __tablename__ = "location_nodes"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    case_id = Column(
        Integer,
        ForeignKey("cases.id"),
        nullable=False,
        index=True
    )

    name = Column(
        String(200),
        nullable=False
    )

    location_type = Column(
        String(50),
        nullable=False,
        default="CRIME_SCENE" # TOWER_SECTOR, SAFE_HOUSE, ANPR_CHECKPOINT, CRIME_SCENE, DOCK_PORT
    )

    latitude = Column(
        Float,
        nullable=False
    )

    longitude = Column(
        Float,
        nullable=False
    )

    address = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )


# ============================================================
# SPATIAL EVENT MODEL (GIS)
# ============================================================

class SpatialEvent(Base):
    __tablename__ = "spatial_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    case_id = Column(
        Integer,
        ForeignKey("cases.id"),
        nullable=False,
        index=True
    )

    entity_name = Column(
        String(100),
        nullable=False
    )

    entity_type = Column(
        String(50),
        nullable=False,
        default="PERSON" # PERSON, PHONE, VEHICLE, ORGANISATION
    )

    location_id = Column(
        Integer,
        ForeignKey("location_nodes.id"),
        nullable=False
    )

    timestamp = Column(
        DateTime(timezone=True),
        nullable=False
    )

    confidence_score = Column(
        Float,
        nullable=False,
        default=1.0
    )

    source_document = Column(
        String(255),
        nullable=True
    )


# ============================================================
# HUMAN-IN-THE-LOOP REVIEW QUEUE MODEL
# ============================================================

class ReviewItem(Base):
    __tablename__ = "review_items"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    case_id = Column(
        Integer,
        ForeignKey("cases.id"),
        nullable=False,
        index=True
    )

    suggestion_type = Column(
        String(50),
        nullable=False # ENTITY_MATCH, RELATIONSHIP_EXTRACTION, SPATIAL_ANOMALY
    )

    title = Column(
        String(200),
        nullable=False
    )

    description = Column(
        Text,
        nullable=False
    )

    source_document = Column(
        String(255),
        nullable=True
    )

    confidence_score = Column(
        Float,
        nullable=False,
        default=0.85
    )

    status = Column(
        String(30),
        nullable=False,
        default="PENDING" # PENDING, ACCEPTED, REJECTED, PARKED_BELOW_THRESHOLD
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )


# ============================================================
# ENTITY MODEL (GRAPH & GIS)
# ============================================================

class Entity(Base):
    __tablename__ = "entities"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    case_id = Column(
        Integer,
        ForeignKey("cases.id"),
        nullable=False,
        index=True
    )

    entity_type = Column(
        String(50),
        nullable=False,
        default="PERSON"
    )

    label = Column(
        String(200),
        nullable=False
    )

    aliases = Column(
        Text,
        nullable=True
    )

    source_document_id = Column(
        Integer,
        nullable=True
    )

    extraction_method = Column(
        String(50),
        nullable=True,
        default="AI_EXTRACTION"
    )

    confidence_score = Column(
        Float,
        nullable=False,
        default=0.95
    )

    verification_status = Column(
        String(30),
        nullable=False,
        default="verified"
    )

    latitude = Column(
        Float,
        nullable=True
    )

    longitude = Column(
        Float,
        nullable=True
    )

    merged_into_id = Column(
        Integer,
        ForeignKey("entities.id"),
        nullable=True
    )

    reviewed_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True
    )

    reviewed_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    review_reason = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )


# ============================================================
# RELATIONSHIP MODEL (GRAPH)
# ============================================================

class Relationship(Base):
    __tablename__ = "relationships"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    case_id = Column(
        Integer,
        ForeignKey("cases.id"),
        nullable=False,
        index=True
    )

    source_entity_id = Column(
        Integer,
        ForeignKey("entities.id"),
        nullable=False
    )

    target_entity_id = Column(
        Integer,
        ForeignKey("entities.id"),
        nullable=False
    )

    relationship_type = Column(
        String(100),
        nullable=False
    )

    evidence_sentence = Column(
        Text,
        nullable=True
    )

    source_document_id = Column(
        Integer,
        nullable=True
    )

    confidence_score = Column(
        Float,
        nullable=False,
        default=0.90
    )

    verification_status = Column(
        String(30),
        nullable=False,
        default="verified"
    )

    reviewed_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True
    )

    reviewed_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    review_reason = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )


# ============================================================
# BLOCKCHAIN CHAIN OF CUSTODY LOG MODEL
# ============================================================

class ChainOfCustodyLog(Base):
    __tablename__ = "chain_of_custody_logs"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    case_id = Column(
        Integer,
        ForeignKey("cases.id"),
        nullable=False,
        index=True
    )

    document_id = Column(
        Integer,
        ForeignKey("documents.id"),
        nullable=True
    )

    action = Column(
        String(100),
        nullable=False # EVIDENCE_UPLOAD, HASH_GENERATED, SMART_CONTRACT_REGISTERED, INVESTIGATOR_ACCESS, TAMPER_VERIFIED
    )

    sha256_hash = Column(
        String(64),
        nullable=False
    )

    actor_name = Column(
        String(100),
        nullable=False
    )

    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )


# ============================================================
# LOCATION MODEL (GIS WAYPOINTS & PLACES)
# ============================================================

class Location(Base):
    __tablename__ = "locations"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    case_id = Column(
        Integer,
        ForeignKey("cases.id"),
        nullable=False,
        index=True
    )

    entity_id = Column(
        Integer,
        ForeignKey("entities.id"),
        nullable=True
    )

    label = Column(
        String(200),
        nullable=False
    )

    latitude = Column(
        Float,
        nullable=False
    )

    longitude = Column(
        Float,
        nullable=False
    )

    location_type = Column(
        String(50),
        nullable=False,
        default="waypoint"
    )

    address_text = Column(
        Text,
        nullable=True
    )

    verification_status = Column(
        String(30),
        nullable=False,
        default="verified"
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
