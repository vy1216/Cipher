import os
import logging
from typing import Optional, Dict, Any, List

logger = logging.getLogger("cipher.neo4j")

class Neo4jService:
    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "cipher_password")
        self.driver = None
        self._connected = False
        self._init_driver()

    def _init_driver(self):
        try:
            from neo4j import GraphDatabase
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            # Test connectivity
            with self.driver.session() as session:
                result = session.run("RETURN 1 AS connected")
                if result.single()["connected"] == 1:
                    self._connected = True
                    logger.info(f"Connected to Neo4j at {self.uri}")
        except Exception as e:
            self._connected = False
            logger.warning(f"Neo4j is not reachable at {self.uri} ({e}). Graph queries will use relational database fallback.")

    def is_available(self) -> bool:
        if not self._connected and self.driver:
            try:
                with self.driver.session() as session:
                    res = session.run("RETURN 1 AS connected")
                    self._connected = (res.single()["connected"] == 1)
            except Exception:
                self._connected = False
        return self._connected

    def close(self):
        if self.driver:
            try:
                self.driver.close()
            except Exception:
                pass

    def sync_case(self, case_id: int, title: str, description: Optional[str] = None):
        if not self.is_available():
            return
        query = """
        MERGE (c:Case {case_id: $case_id})
        SET c.title = $title, c.description = $description, c.updated_at = timestamp()
        """
        try:
            with self.driver.session() as session:
                session.run(query, case_id=case_id, title=title, description=description or "")
        except Exception as e:
            logger.error(f"Failed to sync case {case_id} to Neo4j: {e}")

    def sync_entity(self, case_id: int, entity_data: Dict[str, Any]):
        if not self.is_available():
            return
        query = """
        MERGE (e:Entity {id: $id, case_id: $case_id})
        SET e.name = $name,
            e.type = $type,
            e.role = $role,
            e.confidence = $confidence,
            e.latitude = $latitude,
            e.longitude = $longitude,
            e.verification_status = $verification_status,
            e.updated_at = timestamp()
        WITH e
        MATCH (c:Case {case_id: $case_id})
        MERGE (e)-[:BELONGS_TO]->(c)
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    id=str(entity_data.get("id")),
                    case_id=case_id,
                    name=entity_data.get("name", ""),
                    type=entity_data.get("type", "UNKNOWN"),
                    role=entity_data.get("role", ""),
                    confidence=float(entity_data.get("confidence", 1.0)),
                    latitude=entity_data.get("latitude"),
                    longitude=entity_data.get("longitude"),
                    verification_status=entity_data.get("verification_status", "verified")
                )
        except Exception as e:
            logger.error(f"Failed to sync entity {entity_data.get('id')} to Neo4j: {e}")

    def delete_entity(self, case_id: int, entity_id: str):
        if not self.is_available():
            return
        query = """
        MATCH (e:Entity {id: $id, case_id: $case_id})
        DETACH DELETE e
        """
        try:
            with self.driver.session() as session:
                session.run(query, id=str(entity_id), case_id=case_id)
        except Exception as e:
            logger.error(f"Failed to delete entity {entity_id} from Neo4j: {e}")

    def sync_relationship(self, case_id: int, rel_data: Dict[str, Any]):
        if not self.is_available():
            return
        query = """
        MATCH (s:Entity {id: $source_id, case_id: $case_id})
        MATCH (t:Entity {id: $target_id, case_id: $case_id})
        MERGE (s)-[r:RELATED_TO {rel_id: $rel_id, case_id: $case_id}]->(t)
        SET r.type = $rel_type,
            r.confidence = $confidence,
            r.status = $status,
            r.evidence = $evidence,
            r.updated_at = timestamp()
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    case_id=case_id,
                    source_id=str(rel_data.get("source_id")),
                    target_id=str(rel_data.get("target_id")),
                    rel_id=str(rel_data.get("id")),
                    rel_type=rel_data.get("relationship_type", "CONNECTED"),
                    confidence=float(rel_data.get("confidence", 1.0)),
                    status=rel_data.get("status", "verified"),
                    evidence=rel_data.get("evidence_sentence", "")
                )
        except Exception as e:
            logger.error(f"Failed to sync relationship {rel_data.get('id')} to Neo4j: {e}")

    def delete_relationship(self, case_id: int, rel_id: str):
        if not self.is_available():
            return
        query = """
        MATCH ()-[r:RELATED_TO {rel_id: $rel_id, case_id: $case_id}]->()
        DELETE r
        """
        try:
            with self.driver.session() as session:
                session.run(query, rel_id=str(rel_id), case_id=case_id)
        except Exception as e:
            logger.error(f"Failed to delete relationship {rel_id} from Neo4j: {e}")

    def find_shortest_path(self, case_id: int, start_id: str, end_id: str) -> Optional[Dict[str, Any]]:
        if not self.is_available():
            return None
        query = """
        MATCH (start:Entity {id: $start_id, case_id: $case_id}),
              (end:Entity {id: $end_id, case_id: $case_id})
        MATCH p = shortestPath((start)-[:RELATED_TO*]-(end))
        WHERE ALL(r IN relationships(p) WHERE r.status = 'verified')
        RETURN [node in nodes(p) | node.id] AS node_ids,
               [node in nodes(p) | node.name] AS node_names,
               [r in relationships(p) | r.rel_id] AS edge_ids,
               length(p) AS hops
        """
        try:
            with self.driver.session() as session:
                result = session.run(query, case_id=case_id, start_id=str(start_id), end_id=str(end_id))
                record = result.single()
                if record:
                    return {
                        "found": True,
                        "hops": record["hops"],
                        "node_ids": record["node_ids"],
                        "node_names": record["node_names"],
                        "edge_ids": record["edge_ids"]
                    }
                return {"found": False, "hops": 0, "node_ids": [], "edge_ids": []}
        except Exception as e:
            logger.error(f"Neo4j shortest path error: {e}")
            return None

    def get_entity_connections(self, case_id: int, entity_id: str, hops: int = 1) -> Optional[List[Dict[str, Any]]]:
        if not self.is_available():
            return None
        query = f"""
        MATCH (e:Entity {{id: $entity_id, case_id: $case_id}})
        MATCH (e)-[r:RELATED_TO*1..{hops}]-(connected:Entity)
        RETURN DISTINCT connected.id AS id, connected.name AS name, connected.type AS type
        """
        try:
            with self.driver.session() as session:
                result = session.run(query, case_id=case_id, entity_id=str(entity_id))
                return [dict(record) for record in result]
        except Exception as e:
            logger.error(f"Neo4j entity connections error: {e}")
            return None

    def get_case_subgraph(self, case_id: int) -> Optional[Dict[str, Any]]:
        if not self.is_available():
            return None
        query = """
        MATCH (e:Entity {case_id: $case_id})
        OPTIONAL MATCH (e)-[r:RELATED_TO {case_id: $case_id}]->(t:Entity {case_id: $case_id})
        WHERE r.status = 'verified'
        RETURN collect(DISTINCT {
            id: e.id,
            name: e.name,
            type: e.type,
            role: e.role,
            confidence: e.confidence,
            latitude: e.latitude,
            longitude: e.longitude
        }) AS nodes,
        collect(DISTINCT {
            id: r.rel_id,
            source: e.id,
            target: t.id,
            type: r.type,
            confidence: r.confidence,
            evidence: r.evidence
        }) AS edges
        """
        try:
            with self.driver.session() as session:
                result = session.run(query, case_id=case_id)
                record = result.single()
                if record:
                    # Clean null edges
                    clean_edges = [e for e in record["edges"] if e and e.get("id") and e.get("target")]
                    return {
                        "nodes": record["nodes"],
                        "edges": clean_edges
                    }
                return None
        except Exception as e:
            logger.error(f"Neo4j subgraph fetch error: {e}")
            return None

# Global instance
neo4j_service = Neo4jService()
