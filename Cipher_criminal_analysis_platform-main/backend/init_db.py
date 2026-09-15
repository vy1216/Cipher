import sys
import os
import hashlib
from datetime import datetime

from database import engine, Base, SessionLocal
from models import (
    User, Case, Document, LocationNode, SpatialEvent, ReviewItem,
    ChainOfCustodyLog, Entity, Relationship, Location
)
from auth import hash_password

def init_db():
    print("[CIPHER DB INIT] Creating all tables...")
    Base.metadata.create_all(bind=engine)
    print("[CIPHER DB INIT] Tables created successfully.")

    db = SessionLocal()
    try:
        # Check if baseline user exists
        user_count = db.query(User).count()
        if user_count == 0:
            print("[CIPHER DB INIT] Seeding initial admin and investigator users...")
            admin_user = User(
                full_name="Chief Intelligence Officer",
                email="admin@cipher.intel",
                password_hash=hash_password("CipherAdmin2026!"),
                role="ADMIN"
            )
            investigator_user = User(
                full_name="Lead Investigator",
                email="investigator@cipher.intel",
                password_hash=hash_password("Investigator2026!"),
                role="INVESTIGATOR"
            )
            db.add(admin_user)
            db.add(investigator_user)
            db.commit()
            db.refresh(admin_user)
            db.refresh(investigator_user)
            admin_id = admin_user.id
            investigator_id = investigator_user.id
        else:
            first_user = db.query(User).first()
            admin_id = first_user.id
            investigator_id = first_user.id

        # Check if baseline case exists
        case_count = db.query(Case).count()
        if case_count == 0:
            print("[CIPHER DB INIT] Seeding baseline Case #CN-2026-0143 (Falcon-77 Smuggling Ring)...")
            case = Case(
                id=1,
                case_number="CN-2026-0143",
                title="Operation Falcon-77: Gold & Narcotics Syndicate",
                description="Cross-border illicit gold smuggling and communications network operating across Mumbai Metropolitan Region.",
                status="OPEN",
                priority="HIGH",
                created_by=admin_id
            )
            db.add(case)
            db.commit()

            # Seed Entities
            entities_data = [
                {"id": 1, "type": "PERSON", "label": "Tariq Falcon", "aliases": "The Falcon, Chief Operative", "lat": 18.9438, "lng": 72.8358},
                {"id": 2, "type": "PERSON", "label": "Vikram Seth", "aliases": "The Fixer, Logistics Lead", "lat": 19.0760, "lng": 72.8777},
                {"id": 3, "type": "PHONE", "label": "+91 98200 11223", "aliases": "Burner SIM #1", "lat": 18.9500, "lng": 72.8400},
                {"id": 4, "type": "VEHICLE", "label": "MH-04-AZ-9988", "aliases": "Black Scorpio Escort", "lat": 19.0178, "lng": 72.8478},
                {"id": 5, "type": "LOCATION", "label": "Kucha Mahajani Gold Vault", "aliases": "Central Safehouse", "lat": 18.9515, "lng": 72.8310},
                {"id": 6, "type": "ORGANISATION", "label": "Apex Bullion Exports Pvt Ltd", "aliases": "Front Company", "lat": 19.0600, "lng": 72.8300},
                {"id": 7, "type": "ACCOUNT", "label": "HDFC-8899-3321", "aliases": "Layering Escrow", "lat": 18.9300, "lng": 72.8300}
            ]

            for ed in entities_data:
                e = Entity(
                    id=ed["id"],
                    case_id=1,
                    entity_type=ed["type"],
                    label=ed["label"],
                    aliases=ed["aliases"],
                    confidence_score=0.95,
                    verification_status="verified",
                    latitude=ed["lat"],
                    longitude=ed["lng"]
                )
                db.add(e)
            db.commit()

            # Seed Relationships
            rels_data = [
                {"src": 1, "tgt": 2, "type": "COMMANDS", "evidence": "Tariq Falcon instructed Vikram Seth on shipping routes."},
                {"src": 1, "tgt": 3, "type": "USES_PHONE", "evidence": "Intercepted call logs show Tariq Falcon using burner SIM +91 98200 11223."},
                {"src": 2, "tgt": 4, "type": "DRIVES", "evidence": "ANPR cameras registered Vikram Seth operating Black Scorpio MH-04-AZ-9988."},
                {"src": 4, "tgt": 5, "type": "TRANSIT_TO", "evidence": "Scorpio observed delivering sealed consignments to Kucha Mahajani Vault."},
                {"src": 1, "tgt": 6, "type": "BENEFICIAL_OWNER", "evidence": "Financial audit links Tariq Falcon to Apex Bullion Exports."},
                {"src": 6, "tgt": 7, "type": "TRANSFERS_TO", "evidence": "Rs. 3.85 Cr wired from Apex Bullion to HDFC-8899-3321."}
            ]

            for rd in rels_data:
                r = Relationship(
                    case_id=1,
                    source_entity_id=rd["src"],
                    target_entity_id=rd["tgt"],
                    relationship_type=rd["type"],
                    evidence_sentence=rd["evidence"],
                    confidence_score=0.90,
                    verification_status="verified"
                )
                db.add(r)
            db.commit()

            # Seed Locations
            locs_data = [
                {"label": "Kucha Mahajani Gold Vault", "lat": 18.9515, "lng": 72.8310, "type": "SAFE_HOUSE"},
                {"label": "JNPT Port Terminal 3", "lat": 18.9500, "lng": 72.9500, "type": "DOCK_PORT"},
                {"label": "DND Flyway ANPR Checkpoint", "lat": 19.0178, "lng": 72.8478, "type": "ANPR_CHECKPOINT"}
            ]
            for ld in locs_data:
                loc = Location(
                    case_id=1,
                    label=ld["label"],
                    latitude=ld["lat"],
                    longitude=ld["lng"],
                    location_type=ld["type"],
                    verification_status="verified"
                )
                db.add(loc)
            db.commit()

            print("[CIPHER DB INIT] Baseline case and entities successfully seeded.")
        else:
            print("[CIPHER DB INIT] Database already contains cases. Skipping seed.")

    except Exception as e:
        print(f"[CIPHER DB INIT ERROR] {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
