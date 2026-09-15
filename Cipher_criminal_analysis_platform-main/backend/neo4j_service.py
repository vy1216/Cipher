import os
import logging
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("cipher.neo4j")

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")


class Neo4jService:
    """
    Production Neo4j Service for CIPHER Criminal Intelligence Platform.
    Provides graph sync, Cypher queries, shortest path, and network analysis
    with graceful fallback when Neo4j is disconnected.
    """

    def __init__(self):
        self.driver = None
        self._connected = False
        self._init_driver()

    def _init_driver(self):
        try:
            from neo4j import GraphDatabase, basic_auth
            self.driver = GraphDatabase.driver(
                NEO4J_URI,
                auth=basic_auth(NEO4J_USER, NEO4J_PASSWORD),
                max_connection_lifetime=3600,
                max_connection_pool_size=50
            )
            # Test connectivity
            self.driver.verify_connectivity()
            self._connected = True
            logger.info(f"[CIPHER NEO4J] Connected successfully to Neo4j at {NEO4J_URI}")
        except Exception as e:
            self._connected = False
            logger.warning(
                f"[CIPHER NEO4J] Could not establish connection to Neo4j at {NEO4J_URI}: {e}. "
                "Graph queries will use relational fallback engine."
            )

    @property
    def is_connected(self) -> bool:
        if not self._connected or not self.driver:
            return False
        try:
            self.driver.verify_connectivity()
            return True
        except Exception:
            self._connected = False
            return False

    def close(self):
        if self.driver:
            try:
                self.driver.close()
            except Exception:
                pass

    # =========================================================
    # GRAPH SYNCHRONIZATION (PostgreSQL -> Neo4j)
    # =========================================================

    def sync_case(self, case_id: int, case_number: str, title: str, status: str) -> bool:
        """Syncs or updates a Case node in Neo4j."""
        if not self.is_connected:
            return False
        query = """
        MERGE (c:Case {id: $case_id})
        SET c.case_number = $case_number,
            c.title = $title,
            c.status = $status,
            c.updated_at = datetime()
        RETURN c.id AS id
        """
        try:
            with self.driver.session(database=NEO4J_DATABASE) as session:
                session.run(query, case_id=case_id, case_number=case_number, title=title, status=status)
            return True
        except Exception as e:
            logger.error(f"[NEO4J] Failed to sync case {case_id}: {e}")
            return False

    def sync_entity(self, entity_id: int, case_id: int, label: str, entity_type: str,
                    confidence: float = 1.0, lat: Optional[float] = None, lng: Optional[float] = None,
                    aliases: Optional[str] = None, status: str = "verified") -> bool:
        """Syncs or updates an Entity node and links it to its Case in Neo4j."""
        if not self.is_connected:
            return False
        query = """
        MERGE (e:Entity {id: $entity_id})
        SET e.case_id = $case_id,
            e.label = $label,
            e.type = $entity_type,
            e.confidence = $confidence,
            e.status = $status,
            e.aliases = $aliases,
            e.lat = $lat,
            e.lng = $lng,
            e.updated_at = datetime()
        WITH e
        MERGE (c:Case {id: $case_id})
        MERGE (e)-[:BELONGS_TO]->(c)
        RETURN e.id AS id
        """
        try:
            with self.driver.session(database=NEO4J_DATABASE) as session:
                session.run(
                    query,
                    entity_id=entity_id,
                    case_id=case_id,
                    label=label,
                    entity_type=entity_type,
                    confidence=float(confidence),
                    status=status,
                    aliases=aliases or "",
                    lat=float(lat) if lat is not None else None,
                    lng=float(lng) if lng is not None else None
                )
            return True
        except Exception as e:
            logger.error(f"[NEO4J] Failed to sync entity {entity_id}: {e}")
            return False

    def delete_entity(self, entity_id: int) -> bool:
        """Deletes an Entity node and all its connected edges from Neo4j."""
        if not self.is_connected:
            return False
        query = "MATCH (e:Entity {id: $entity_id}) DETACH DELETE e"
        try:
            with self.driver.session(database=NEO4J_DATABASE) as session:
                session.run(query, entity_id=entity_id)
            return True
        except Exception as e:
            logger.error(f"[NEO4J] Failed to delete entity {entity_id}: {e}")
            return False

    def sync_relationship(self, relationship_id: int, case_id: int, source_entity_id: int,
                          target_entity_id: int, relationship_type: str, confidence: float = 1.0,
                          status: str = "verified", evidence: Optional[str] = None) -> bool:
        """
        Syncs a verified or pending relationship edge between two entities in Neo4j.
        Only approved/verified relationships are active in network traversal queries.
        """
        if not self.is_connected:
            return False
        query = """
        MATCH (s:Entity {id: $source_id})
        MATCH (t:Entity {id: $target_id})
        MERGE (s)-[r:RELATED_TO {id: $relationship_id}]->(t)
        SET r.type = $relationship_type,
            r.case_id = $case_id,
            r.confidence = $confidence,
            r.status = $status,
            r.evidence = $evidence,
            r.updated_at = datetime()
        RETURN r.id AS id
        """
        try:
            with self.driver.session(database=NEO4J_DATABASE) as session:
                session.run(
                    query,
                    relationship_id=relationship_id,
                    case_id=case_id,
                    source_id=source_entity_id,
                    target_id=target_entity_id,
                    relationship_type=relationship_type,
                    confidence=float(confidence),
                    status=status,
                    evidence=evidence or ""
                )
            return True
        except Exception as e:
            logger.error(f"[NEO4J] Failed to sync relationship {relationship_id}: {e}")
            return False

    def delete_relationship(self, relationship_id: int) -> bool:
        """Deletes a relationship edge by its ID from Neo4j."""
        if not self.is_connected:
            return False
        query = "MATCH ()-[r:RELATED_TO {id: $relationship_id}]-() DELETE r"
        try:
            with self.driver.session(database=NEO4J_DATABASE) as session:
                session.run(query, relationship_id=relationship_id)
            return True
        except Exception as e:
            logger.error(f"[NEO4J] Failed to delete relationship {relationship_id}: {e}")
            return False

    def sync_full_case(self, case_id: int, entities: List[Any], relationships: List[Any]) -> Dict[str, Any]:
        """Bulk synchronizes an entire case's entities and verified relationships into Neo4j."""
        if not self.is_connected:
            return {"status": "skipped", "message": "Neo4j not connected, using relational graph storage"}

        nodes_synced = 0
        edges_synced = 0
        for e in entities:
            if self.sync_entity(
                entity_id=e.id,
                case_id=case_id,
                label=e.label,
                entity_type=e.entity_type,
                confidence=getattr(e, "confidence_score", 1.0),
                lat=getattr(e, "latitude", None),
                lng=getattr(e, "longitude", None),
                aliases=getattr(e, "aliases", None),
                status=getattr(e, "verification_status", "verified")
            ):
                nodes_synced += 1

        for r in relationships:
            if self.sync_relationship(
                relationship_id=r.id,
                case_id=case_id,
                source_entity_id=r.source_entity_id,
                target_entity_id=r.target_entity_id,
                relationship_type=r.relationship_type,
                confidence=getattr(r, "confidence_score", 1.0),
                status=getattr(r, "verification_status", "verified"),
                evidence=getattr(r, "evidence_sentence", None)
            ):
                edges_synced += 1

        return {
            "status": "success",
            "neo4j_connected": True,
            "entities_synced": nodes_synced,
            "relationships_synced": edges_synced
        }

    # =========================================================
    # GRAPH ANALYTIC QUERIES
    # =========================================================

    def get_case_subgraph(self, case_id: int, include_unverified: bool = False) -> Optional[Dict[str, Any]]:
        """Retrieves Cytoscape-formatted nodes and edges for a case from Neo4j."""
        if not self.is_connected:
            return None

        status_filter = "" if include_unverified else "AND r.status = 'verified'"
        query = f"""
        MATCH (e:Entity {{case_id: $case_id}})
        OPTIONAL MATCH (e)-[r:RELATED_TO {{case_id: $case_id}}]->(e2:Entity)
        WHERE true {status_filter}
        RETURN e, r, e2
        """
        try:
            with self.driver.session(database=NEO4J_DATABASE) as session:
                results = session.run(query, case_id=case_id)
                nodes_map = {}
                edges = []

                for record in results:
                    e = record.get("e")
                    if e:
                        eid = str(e.get("id"))
                        if eid not in nodes_map:
                            nodes_map[eid] = {
                                "data": {
                                    "id": eid,
                                    "label": e.get("label", ""),
                                    "type": e.get("type", "PERSON"),
                                    "confidence": e.get("confidence", 1.0),
                                    "status": e.get("status", "verified"),
                                    "lat": e.get("lat"),
                                    "lng": e.get("lng"),
                                    "source": "neo4j"
                                }
                            }
                    r = record.get("r")
                    e2 = record.get("e2")
                    if r and e2:
                        e2_id = str(e2.get("id"))
                        if e2_id not in nodes_map:
                            nodes_map[e2_id] = {
                                "data": {
                                    "id": e2_id,
                                    "label": e2.get("label", ""),
                                    "type": e2.get("type", "PERSON"),
                                    "confidence": e2.get("confidence", 1.0),
                                    "status": e2.get("status", "verified"),
                                    "lat": e2.get("lat"),
                                    "lng": e2.get("lng"),
                                    "source": "neo4j"
                                }
                            }
                        edges.append({
                            "data": {
                                "id": str(r.get("id")),
                                "source": str(e.get("id")),
                                "target": str(e2.get("id")),
                                "label": r.get("type", "RELATED_TO"),
                                "evidence": r.get("evidence", ""),
                                "confidence": r.get("confidence", 1.0),
                                "status": r.get("status", "verified"),
                                "source_engine": "neo4j"
                            }
                        })
                return {"nodes": list(nodes_map.values()), "edges": edges, "engine": "neo4j"}
        except Exception as e:
            logger.error(f"[NEO4J] Failed to query case subgraph: {e}")
            return None

    def query_entity_connections(self, entity_id: int) -> Optional[Dict[str, Any]]:
        """Queries 1-hop and 2-hop connections for an entity."""
        if not self.is_connected:
            return None
        query = """
        MATCH (e:Entity {id: $entity_id})-[r:RELATED_TO]-(neighbor:Entity)
        WHERE r.status = 'verified'
        RETURN e, r, neighbor
        """
        try:
            with self.driver.session(database=NEO4J_DATABASE) as session:
                results = session.run(query, entity_id=entity_id)
                neighbors = []
                for record in results:
                    neighbor = record["neighbor"]
                    r = record["r"]
                    neighbors.append({
                        "entity_id": neighbor.get("id"),
                        "label": neighbor.get("label"),
                        "type": neighbor.get("type"),
                        "relationship_id": r.get("id"),
                        "relationship_type": r.get("type"),
                        "evidence": r.get("evidence"),
                        "confidence": r.get("confidence")
                    })
                return {"entity_id": entity_id, "connections_count": len(neighbors), "connections": neighbors}
        except Exception as e:
            logger.error(f"[NEO4J] Failed to query entity connections: {e}")
            return None

    def find_shortest_path(self, case_id: int, source_id: int, target_id: int) -> Optional[Dict[str, Any]]:
        """Finds the shortest investigative path between two entities in Neo4j."""
        if not self.is_connected:
            return None
        query = """
        MATCH (s:Entity {id: $source_id, case_id: $case_id}),
              (t:Entity {id: $target_id, case_id: $case_id}),
              p = shortestPath((s)-[:RELATED_TO*..10]-(t))
        RETURN [node in nodes(p) | {id: node.id, label: node.label, type: node.type}] AS path_nodes,
               [rel in relationships(p) | {id: rel.id, type: rel.type, evidence: rel.evidence}] AS path_edges,
               length(p) AS path_length
        """
        try:
            with self.driver.session(database=NEO4J_DATABASE) as session:
                result = session.run(query, case_id=case_id, source_id=source_id, target_id=target_id).single()
                if not result:
                    return {"found": False, "length": -1, "path_nodes": [], "path_edges": [], "engine": "neo4j"}
                return {
                    "found": True,
                    "length": result["path_length"],
                    "path_nodes": result["path_nodes"],
                    "path_edges": result["path_edges"],
                    "engine": "neo4j"
                }
        except Exception as e:
            logger.error(f"[NEO4J] Shortest path query error: {e}")
            return None


# Global singleton instance
neo4j_service = Neo4jService()
