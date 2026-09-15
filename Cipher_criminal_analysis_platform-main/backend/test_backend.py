import pytest
from fastapi.testclient import TestClient
from .main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "database" in data

def test_login_and_auth_flow():
    # Login with default seeded admin
    login_resp = client.post("/auth/login", json={
        "username": "admin",
        "password": "Admin@123"
    })
    assert login_resp.status_code == 200
    token_data = login_resp.json()
    assert "token" in token_data
    token = token_data["token"]

    # Verify /auth/me with Bearer token
    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["role"] == "ADMIN"

def test_prevent_public_admin_registration():
    import time
    ts = int(time.time() * 1000)
    # Public registration attempting to set role=ADMIN without secret must be rejected
    reg_resp = client.post("/auth/register", json={
        "username": f"hacker_{ts}",
        "email": f"hacker_{ts}@test.com",
        "password": "Password@123",
        "role": "ADMIN"
    })
    assert reg_resp.status_code == 403

    # Normal investigator registration succeeds
    reg_ok = client.post("/auth/register", json={
        "username": f"agent_{ts}",
        "email": f"agent_{ts}@test.com",
        "password": "Password@123",
        "role": "INVESTIGATOR"
    })
    assert reg_ok.status_code == 200
    assert reg_ok.json()["user"]["role"] == "INVESTIGATOR"

def test_cases_crud_and_search():
    # List cases
    cases_resp = client.get("/cases")
    assert cases_resp.status_code == 200
    data = cases_resp.json()
    assert "cases" in data
    assert len(data["cases"]) > 0

    # Get Case 1 details
    case1_resp = client.get("/cases/1")
    assert case1_resp.status_code == 200
    assert case1_resp.json()["id"] == 1

def test_relationship_review_workflow():
    # 1. Create a candidate relationship with pending status
    entities_resp = client.get("/cases/1/entities")
    assert entities_resp.status_code == 200
    entities = entities_resp.json()
    assert len(entities) >= 2
    src_id = entities[0]["id"]
    tgt_id = entities[1]["id"]

    rel_resp = client.post("/cases/1/relationships", json={
        "source_id": str(src_id),
        "target_id": str(tgt_id),
        "relationship_type": "SUSPECTED_ASSOCIATE",
        "confidence": 0.82,
        "evidence_sentence": "Observed meeting in lobby.",
        "status": "pending"
    })
    assert rel_resp.status_code == 200
    rel_id = rel_resp.json()["id"]

    # 2. Check pending list
    pending_resp = client.get(f"/cases/1/relationships/pending?status=pending")
    assert pending_resp.status_code == 200
    pending_list = pending_resp.json()
    found = any(str(r["id"]) == str(rel_id) for r in pending_list)
    assert found, f"Created relationship {rel_id} should be in pending list"

    # 3. Approve relationship
    approve_resp = client.post(f"/cases/1/relationships/{rel_id}/approve", params={"reason": "Verified via CCTV footage"})
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "success"

def test_gis_locations_and_geojson():
    # GeoJSON FeatureCollection endpoint
    gis_resp = client.get("/cases/1/gis-data")
    assert gis_resp.status_code == 200
    geojson = gis_resp.json()
    assert geojson["type"] == "FeatureCollection"
    assert "features" in geojson
    assert len(geojson["features"]) > 0

    # Nearby radius search
    nearby_resp = client.get("/cases/1/gis/nearby?latitude=18.9220&longitude=72.8347&radius_meters=10000")
    assert nearby_resp.status_code == 200
    nearby_data = nearby_resp.json()
    assert "results" in nearby_data

def test_graph_analytics_and_path():
    # Graph data
    graph_resp = client.get("/cases/1/graph")
    assert graph_resp.status_code == 200
    graph = graph_resp.json()
    assert "nodes" in graph
    assert "edges" in graph

    # Centrality
    centrality_resp = client.post("/cases/1/graph/analytics/centrality")
    assert centrality_resp.status_code == 200
    assert "rankings" in centrality_resp.json()

    # Community detection
    comm_resp = client.post("/cases/1/graph/analytics/communities")
    assert comm_resp.status_code == 200
    assert "communities" in comm_resp.json()

def test_entity_duplicate_detection():
    dup_resp = client.get("/cases/1/entities/duplicates")
    assert dup_resp.status_code == 200
    assert "potential_duplicates" in dup_resp.json()
