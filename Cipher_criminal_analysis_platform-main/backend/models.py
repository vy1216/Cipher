import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, Float, Text, DateTime, ForeignKey, Boolean
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_property
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    full_name = Column(String(200), nullable=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="INVESTIGATOR", nullable=False) # INVESTIGATOR, ANALYST, ADMIN
    created_at = Column(String(100), default=lambda: datetime.datetime.utcnow().isoformat())

    cases = relationship("Case", back_populates="creator")

    @property
    def display_name(self):
        return self.full_name or self.username or self.email

    @property
    def is_active(self):
        return True

class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_number = Column(String(100), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), default="ACTIVE") # ACTIVE, CLOSED, UNDER_REVIEW
    priority = Column(String(50), default="HIGH") # LOW, MEDIUM, HIGH, CRITICAL
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(String(100), default=lambda: datetime.datetime.utcnow().isoformat())
    updated_at = Column(String(100), default=lambda: datetime.datetime.utcnow().isoformat())

    creator = relationship("User", back_populates="cases")
    documents = relationship("Document", back_populates="case", cascade="all, delete-orphan")
    entities = relationship("Entity", back_populates="case", cascade="all, delete-orphan")
    relationships = relationship("Relationship", back_populates="case", cascade="all, delete-orphan")

    @hybrid_property
    def user_id(self):
        return self.created_by

    @user_id.setter
    def user_id(self, val):
        self.created_by = val

    @user_id.expression
    def user_id(cls):
        return cls.created_by

    @property
    def lead_investigator(self):
        return self.creator.display_name if self.creator else "Lead Investigator"

    @lead_investigator.setter
    def lead_investigator(self, val):
        pass

class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String(255), nullable=False)
    file_type = Column(String(50), nullable=False)
    file_path = Column(String(500), nullable=False)
    processing_status = Column(String(50), default="UPLOADED") # UPLOADED, PROCESSING, COMPLETED, FAILED
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    uploaded_at = Column(String(100), default=lambda: datetime.datetime.utcnow().isoformat())
    error_message = Column(Text, nullable=True)
    file_size_bytes = Column(Integer, default=0)
    mime_type = Column(String(100), nullable=True)

    case = relationship("Case", back_populates="documents")

    @hybrid_property
    def status(self):
        return self.processing_status

    @status.setter
    def status(self, val):
        self.processing_status = val

    @status.expression
    def status(cls):
        return cls.processing_status

    @hybrid_property
    def file_size(self):
        return self.file_size_bytes

    @file_size.setter
    def file_size(self, val):
        self.file_size_bytes = val

    @property
    def uploader_id(self):
        return self.uploaded_by

    @uploader_id.setter
    def uploader_id(self, val):
        self.uploaded_by = val

    @property
    def created_at(self):
        return self.uploaded_at

class Entity(Base):
    __tablename__ = "entities"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_type = Column(String(50), nullable=False, index=True) # PERSON, ORGANIZATION, VEHICLE, PHONE, FINANCIAL, LOCATION, EVIDENCE
    label = Column(String(255), nullable=False, index=True)
    aliases = Column(Text, nullable=True)
    source_document_id = Column(Integer, ForeignKey("documents.id", ondelete="SET NULL"), nullable=True)
    extraction_method = Column(String(100), default="AI_EXTRACTION")
    confidence_score = Column(Float, default=0.95)
    verification_status = Column(String(50), default="verified") # candidate, verified, rejected
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    created_at = Column(String(100), default=lambda: datetime.datetime.utcnow().isoformat())
    merged_into_id = Column(Integer, nullable=True)
    reviewed_by = Column(Integer, nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_reason = Column(Text, nullable=True)

    case = relationship("Case", back_populates="entities")

    def __init__(self, **kwargs):
        if "name" in kwargs and "label" not in kwargs:
            kwargs["label"] = kwargs.pop("name")
        if "type" in kwargs and "entity_type" not in kwargs:
            kwargs["entity_type"] = kwargs.pop("type")
        if "confidence" in kwargs and "confidence_score" not in kwargs:
            kwargs["confidence_score"] = kwargs.pop("confidence")
        if "status" in kwargs and "verification_status" not in kwargs:
            kwargs["verification_status"] = kwargs.pop("status")
        if "id" in kwargs and isinstance(kwargs["id"], str):
            clean = kwargs["id"].replace("ent-", "")
            if clean.isdigit():
                kwargs["id"] = int(clean)
            else:
                kwargs.pop("id", None)
        super().__init__(**kwargs)

    @hybrid_property
    def name(self):
        return self.label

    @name.setter
    def name(self, val):
        self.label = val

    @name.expression
    def name(cls):
        return cls.label

    @hybrid_property
    def type(self):
        return self.entity_type

    @type.setter
    def type(self, val):
        self.entity_type = val

    @type.expression
    def type(cls):
        return cls.entity_type

    @property
    def role(self):
        return self.entity_type

    @hybrid_property
    def confidence(self):
        return self.confidence_score

    @confidence.setter
    def confidence(self, val):
        self.confidence_score = val

    @confidence.expression
    def confidence(cls):
        return cls.confidence_score

    @hybrid_property
    def status(self):
        return self.verification_status

    @status.setter
    def status(self, val):
        self.verification_status = val

    @status.expression
    def status(cls):
        return cls.verification_status

class Relationship(Base):
    __tablename__ = "relationships"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    source_entity_id = Column(Integer, nullable=False, index=True)
    target_entity_id = Column(Integer, nullable=False, index=True)
    relationship_type = Column(String(100), nullable=False, index=True)
    evidence_sentence = Column(Text, nullable=True)
    source_document_id = Column(Integer, ForeignKey("documents.id", ondelete="SET NULL"), nullable=True)
    confidence_score = Column(Float, default=0.90)
    verification_status = Column(String(50), default="verified", index=True) # pending, verified, rejected
    created_at = Column(String(100), default=lambda: datetime.datetime.utcnow().isoformat())
    reviewed_by = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_reason = Column(Text, nullable=True)

    case = relationship("Case", back_populates="relationships")

    def __init__(self, **kwargs):
        if "source_id" in kwargs and "source_entity_id" not in kwargs:
            src = str(kwargs.pop("source_id")).replace("ent-", "")
            kwargs["source_entity_id"] = int(src) if src.isdigit() else 1
        if "target_id" in kwargs and "target_entity_id" not in kwargs:
            tgt = str(kwargs.pop("target_id")).replace("ent-", "")
            kwargs["target_entity_id"] = int(tgt) if tgt.isdigit() else 2
        if "confidence" in kwargs and "confidence_score" not in kwargs:
            kwargs["confidence_score"] = kwargs.pop("confidence")
        if "status" in kwargs and "verification_status" not in kwargs:
            kwargs["verification_status"] = kwargs.pop("status")
        if "id" in kwargs and isinstance(kwargs["id"], str):
            clean = kwargs["id"].replace("rel-", "")
            if clean.isdigit():
                kwargs["id"] = int(clean)
            else:
                kwargs.pop("id", None)
        super().__init__(**kwargs)

    @hybrid_property
    def source_id(self):
        return str(self.source_entity_id)

    @source_id.setter
    def source_id(self, val):
        clean = str(val).replace("ent-", "")
        self.source_entity_id = int(clean) if clean.isdigit() else 0

    @source_id.expression
    def source_id(cls):
        return cls.source_entity_id

    @hybrid_property
    def target_id(self):
        return str(self.target_entity_id)

    @target_id.setter
    def target_id(self, val):
        clean = str(val).replace("ent-", "")
        self.target_entity_id = int(clean) if clean.isdigit() else 0

    @target_id.expression
    def target_id(cls):
        return cls.target_entity_id

    @hybrid_property
    def confidence(self):
        return self.confidence_score

    @confidence.setter
    def confidence(self, val):
        self.confidence_score = val

    @confidence.expression
    def confidence(cls):
        return cls.confidence_score

    @hybrid_property
    def status(self):
        return self.verification_status

    @status.setter
    def status(self, val):
        self.verification_status = val

    @status.expression
    def status(cls):
        return cls.verification_status

class Location(Base):
    __tablename__ = "locations"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_id = Column(Integer, nullable=True)
    label = Column(String(255), nullable=False)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    location_type = Column(String(100), default="FACILITY")
    address_text = Column(Text, nullable=True)
    source_document_id = Column(Integer, nullable=True)
    verification_status = Column(String(50), default="verified")
    event_timestamp = Column(String(100), default=lambda: datetime.datetime.utcnow().isoformat())
    created_at = Column(String(100), default=lambda: datetime.datetime.utcnow().isoformat())

    def __init__(self, **kwargs):
        if "name" in kwargs and "label" not in kwargs:
            kwargs["label"] = kwargs.pop("name")
        if "address" in kwargs and "address_text" not in kwargs:
            kwargs["address_text"] = kwargs.pop("address")
        super().__init__(**kwargs)

    @hybrid_property
    def name(self):
        return self.label

    @name.setter
    def name(self, val):
        self.label = val

    @name.expression
    def name(cls):
        return cls.label

    @hybrid_property
    def address(self):
        return self.address_text

    @address.setter
    def address(self, val):
        self.address_text = val

    @address.expression
    def address(cls):
        return cls.address_text

    @property
    def accuracy_m(self):
        return 10.0

    @property
    def confidence(self):
        return 1.0

class LocationNode(Base):
    __tablename__ = "location_nodes"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    location_type = Column(String(100), default="POINT")
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    address = Column(Text, nullable=True)
    created_at = Column(String(100), default=lambda: datetime.datetime.utcnow().isoformat())

class SpatialEvent(Base):
    __tablename__ = "spatial_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_name = Column(String(255), nullable=False)
    entity_type = Column(String(50), default="PERSON")
    location_id = Column(Integer, ForeignKey("location_nodes.id", ondelete="CASCADE"), nullable=False)
    timestamp = Column(String(100), default=lambda: datetime.datetime.utcnow().isoformat())
    confidence_score = Column(Float, default=1.0)
    source_document = Column(Text, nullable=True)

class ReviewItem(Base):
    __tablename__ = "review_items"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    suggestion_type = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    source_document = Column(Text, nullable=True)
    confidence_score = Column(Float, default=0.85)
    status = Column(String(50), default="pending")
    reviewed_by = Column(Integer, nullable=True)
    reviewed_at = Column(String(100), nullable=True)
    created_at = Column(String(100), default=lambda: datetime.datetime.utcnow().isoformat())

class ChainOfCustodyLog(Base):
    __tablename__ = "chain_of_custody_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    document_id = Column(Integer, nullable=True)
    action = Column(String(100), nullable=False)
    performed_by = Column(String(100), nullable=False)
    hash_value = Column(String(64), nullable=False)
    previous_hash = Column(String(64), nullable=True)
    timestamp = Column(String(100), default=lambda: datetime.datetime.utcnow().isoformat())
    details = Column(Text, nullable=True)
