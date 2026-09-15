import os
import datetime
import hashlib
from .database import engine, Base, SessionLocal
from .models import User, Case, Entity, Relationship, Location, LocationNode, SpatialEvent, ChainOfCustodyLog
from .auth import get_password_hash
from .neo4j_service import neo4j_service

def init_database():
    print("[CIPHER] Initializing database tables...")
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # Check if admin user exists
        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            admin_user = User(
                username="admin",
                email="admin@cipher.internal",
                password_hash=get_password_hash("Admin@123"),
                full_name="Cipher Director / Lead Admin",
                role="ADMIN"
            )
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)
            print("[CIPHER] Created default administrator: admin / Admin@123")

        # Check if investigator user exists
        inv_user = db.query(User).filter(User.username == "investigator").first()
        if not inv_user:
            inv_user = User(
                username="investigator",
                email="investigator@cipher.internal",
                password_hash=get_password_hash("Investigator@123"),
                full_name="Senior Special Agent",
                role="INVESTIGATOR"
            )
            db.add(inv_user)
            db.commit()
            db.refresh(inv_user)
            print("[CIPHER] Created default investigator: investigator / Investigator@123")

        # Check if Case 1 exists
        sample_case = db.query(Case).filter(Case.id == 1).first()
        if not sample_case:
            sample_case = Case(
                id=1,
                title="Falcon-77 Smuggling Ring",
                case_number="CN-2026-0143",
                description="Cross-border contraband and hawala laundering syndicate operating across Mumbai, Nhava Sheva Docks, and Bhiwandi warehousing corridors.",
                status="ACTIVE",
                priority="CRITICAL",
                lead_investigator="Director Vikram Seth",
                user_id=admin_user.id
            )
            db.add(sample_case)
            db.commit()
            db.refresh(sample_case)
            print("[CIPHER] Seeded primary case #CN-2026-0143")

            # Seed Entities
            entities_data = [
                {"id": "ent-1", "name": "Tariq 'Falcon' Mansoor", "type": "PERSON", "role": "Syndicate Kingpin", "confidence": 0.98, "aliases": "Falcon, The Eagle", "latitude": 18.9220, "longitude": 72.8347},
                {"id": "ent-2", "name": "Bilal 'Cargo' Qureshi", "type": "PERSON", "role": "Logistics Coordinator", "confidence": 0.94, "aliases": "B-Cargo", "latitude": 18.9500, "longitude": 72.8450},
                {"id": "ent-3", "name": "White Scorpio MH-04-AZ-9981", "type": "VEHICLE", "role": "Smuggling Transport", "confidence": 0.96, "aliases": "Scorpio-9981", "latitude": 19.0176, "longitude": 72.8561},
                {"id": "ent-4", "name": "Nhava Sheva Dock Yard B-4", "type": "LOCATION", "role": "Primary Offload Hub", "confidence": 0.99, "aliases": "JNPT Pier 4", "latitude": 18.9502, "longitude": 72.9515},
                {"id": "ent-5", "name": "Bhiwandi Textile Godown 12", "type": "LOCATION", "role": "Stash Warehouse", "confidence": 0.92, "aliases": "Godown-12", "latitude": 19.2970, "longitude": 73.0630},
                {"id": "ent-6", "name": "+91 98201 55432", "type": "PHONE", "role": "Burner Device A", "confidence": 0.95, "aliases": "Burner-A", "latitude": 18.9320, "longitude": 72.8310},
                {"id": "ent-7", "name": "+91 98201 88765", "type": "PHONE", "role": "Burner Device B", "confidence": 0.91, "aliases": "Burner-B", "latitude": 18.9410, "longitude": 72.8390},
                {"id": "ent-8", "name": "Apex Bullion Trading Ltd", "type": "ORGANIZATION", "role": "Hawala Shell Entity", "confidence": 0.97, "aliases": "Apex Bullion", "latitude": 18.9535, "longitude": 72.8322},
                {"id": "ent-9", "name": "HDFC Escrow AC #992819", "type": "FINANCIAL", "role": "Laundering Conduit", "confidence": 0.95, "aliases": "Escrow-992819", "latitude": 18.9315, "longitude": 72.8318},
            ]

            for idx, e in enumerate(entities_data, 1):
                entity_obj = Entity(
                    id=idx,
                    case_id=1,
                    label=e["name"],
                    entity_type=e["type"],
                    confidence_score=e["confidence"],
                    aliases=e["aliases"],
                    latitude=e["latitude"],
                    longitude=e["longitude"],
                    verification_status="verified"
                )
                db.add(entity_obj)
                # Also add to location table if it has coordinates
                if e["latitude"] and e["longitude"]:
                    loc = Location(
                        case_id=1,
                        label=e["name"],
                        location_type=e["type"],
                        latitude=e["latitude"],
                        longitude=e["longitude"],
                        address_text="Mumbai Metropolitan Region",
                        verification_status="verified"
                    )
                    db.add(loc)
                    loc_node = LocationNode(
                        case_id=1,
                        name=e["name"],
                        latitude=e["latitude"],
                        longitude=e["longitude"],
                        location_type=e["type"]
                    )
                    db.add(loc_node)

            db.commit()

            # Seed Relationships (map ent-1 -> 1, ent-2 -> 2 etc.)
            relationships_data = [
                {"id": 1, "source_id": 1, "target_id": 2, "type": "COMMANDS", "confidence": 0.95, "sentence": "Intercepted wiretap indicates Tariq Mansoor instructing Bilal Qureshi on dock arrivals."},
                {"id": 2, "source_id": 1, "target_id": 6, "type": "USES_PHONE", "confidence": 0.99, "sentence": "Tower sector dumps link Mansoor's residence to burner MSISDN +91 98201 55432."},
                {"id": 3, "source_id": 2, "target_id": 7, "type": "USES_PHONE", "confidence": 0.97, "sentence": "CDR analysis links Bilal Qureshi with IMEI registration for burner MSISDN +91 98201 88765."},
                {"id": 4, "source_id": 6, "target_id": 7, "type": "CALLS", "confidence": 0.98, "sentence": "42 encrypted call handshakes recorded between Burner A and Burner B prior to shipment."},
                {"id": 5, "source_id": 2, "target_id": 3, "type": "DRIVES", "confidence": 0.93, "sentence": "Toll plaza ANPR cameras captured Qureshi behind the wheel of Scorpio MH-04-AZ-9981."},
                {"id": 6, "source_id": 3, "target_id": 4, "type": "TRANSIT_TO", "confidence": 0.96, "sentence": "Vehicle registered entering JNPT Pier 4 cargo gate at 02:14 AM."},
                {"id": 7, "source_id": 3, "target_id": 5, "type": "TRANSIT_TO", "confidence": 0.94, "sentence": "Scorpio observed unloading sealed crates at Bhiwandi Godown-12."},
                {"id": 8, "source_id": 1, "target_id": 8, "type": "BENEFICIAL_OWNER", "confidence": 0.97, "sentence": "Corporate registrar filings confirm Tariq Mansoor holds 85% equity in Apex Bullion."},
                {"id": 9, "source_id": 8, "target_id": 9, "type": "TRANSFERS_TO", "confidence": 0.98, "sentence": "Layered wire transfers totaling INR 3.85 Cr routed into escrow AC #992819."}
            ]

            for r in relationships_data:
                rel_obj = Relationship(
                    id=r["id"],
                    case_id=1,
                    source_entity_id=r["source_id"],
                    target_entity_id=r["target_id"],
                    relationship_type=r["type"],
                    confidence_score=r["confidence"],
                    evidence_sentence=r["sentence"],
                    verification_status="verified",
                    reviewed_by="admin"
                )
                db.add(rel_obj)

            # Seed Chain of Custody Initial Entry
            genesis_hash = hashlib.sha256(b"CIPHER_GENESIS_BLOCK_FALCON_77").hexdigest()
            log_entry = ChainOfCustodyLog(
                case_id=1,
                action="CASE_INITIALIZED",
                performed_by="Director Vikram Seth",
                hash_value=genesis_hash,
                previous_hash="0" * 64,
                details="Cryptographic genesis entry for Case #CN-2026-0143."
            )
            db.add(log_entry)
            db.commit()
            print("[CIPHER] Seeded entities, relationships, locations, and genesis chain log.")

            # Sync to Neo4j if available
            if neo4j_service.is_available():
                print("[CIPHER] Syncing seed data to Neo4j...")
                neo4j_service.sync_case(1, sample_case.title, sample_case.description)
                for e in entities_data:
                    neo4j_service.sync_entity(1, e)
                for r in relationships_data:
                    neo4j_service.sync_relationship(1, {
                        "id": r["id"],
                        "source_id": r["source_id"],
                        "target_id": r["target_id"],
                        "relationship_type": r["type"],
                        "confidence": r["confidence"],
                        "status": "verified",
                        "evidence_sentence": r["sentence"]
                    })
                print("[CIPHER] Neo4j sync complete.")

    except Exception as e:
        print(f"[CIPHER] Initialization error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    init_database()
