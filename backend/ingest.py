import json
import os
import hashlib
from backend.database import (
    initialize_database,
    get_connection,
    save_source,
    save_entity,
    save_entity_resolution,
    save_relationship,
    log_audit
)
from backend.analysis import analyze_articles

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
CORPUS_PATH = os.path.join(DATA_DIR, "curated_corpus.json")


def ingest_curated_corpus(investigation_id: int = 1):
    """
    Ingests the curated Indian OSINT corpus into the designated investigation.
    Extracts entities, runs entity resolution, extracts typed relationships,
    and logs the audit trail.
    """
    initialize_database()

    if not os.path.exists(CORPUS_PATH):
        print(f"Error: {CORPUS_PATH} not found.")
        return 0

    with open(CORPUS_PATH, "r", encoding="utf-8") as f:
        docs = json.load(f)

    print(f"Starting ingestion of {len(docs)} documents into Investigation {investigation_id}...")

    conn = get_connection()
    # Fetch existing canonical entities for this investigation
    existing_entities = [
        dict(r) for r in conn.execute(
            "SELECT id, name, entity_type FROM entities WHERE investigation_id = ?",
            (investigation_id,)
        ).fetchall()
    ]
    conn.close()

    ingested_sources = []

    for item in docs:
        title = item.get("title", "")
        url = item.get("url", "")
        domain = item.get("domain", "")
        author = item.get("author", "")
        pub_date = item.get("publication_date", "")
        snippet = item.get("snippet", "")
        content = item.get("content", "")

        doc_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        source_id = save_source(
            title=title,
            url=url,
            domain=domain,
            snippet=snippet,
            content=content,
            author=author,
            publication_date=pub_date,
            investigation_id=investigation_id,
            doc_hash=doc_hash
        )

        ingested_sources.append({
            "source_id": source_id,
            "title": title,
            "content": content,
            "article": {"content": content}
        })

    print(f"Saved {len(ingested_sources)} sources. Running NLP & Entity Resolution...")

    # Run analysis
    analysis_result = analyze_articles(ingested_sources, existing_entities)

    entities_dict = analysis_result.get("entities", {})
    saved_entity_map = {}

    # Save People
    for canonical_name, res in entities_dict.get("people", {}).items():
        eid = save_entity(canonical_name, "person", investigation_id)
        saved_entity_map[canonical_name.lower()] = eid
        if res.get("status") in ["auto_matched", "needs_review"]:
            save_entity_resolution(
                investigation_id=investigation_id,
                alias_name=canonical_name,
                canonical_entity_id=eid,
                match_score=res.get("match_score", 1.0),
                rationale=res.get("rationale", "Rule match"),
                status=res.get("status", "auto_matched")
            )

    # Save Organizations
    for canonical_name, res in entities_dict.get("organizations", {}).items():
        eid = save_entity(canonical_name, "organization", investigation_id)
        saved_entity_map[canonical_name.lower()] = eid
        if res.get("status") in ["auto_matched", "needs_review"]:
            save_entity_resolution(
                investigation_id=investigation_id,
                alias_name=canonical_name,
                canonical_entity_id=eid,
                match_score=res.get("match_score", 1.0),
                rationale=res.get("rationale", "Rule match"),
                status=res.get("status", "auto_matched")
            )

    # Save Locations
    for canonical_name, res in entities_dict.get("locations", {}).items():
        eid = save_entity(canonical_name, "location", investigation_id)
        saved_entity_map[canonical_name.lower()] = eid

    # Save Threats
    for threat in analysis_result.get("threat_indicators", []):
        eid = save_entity(threat, "threat", investigation_id)
        saved_entity_map[threat.lower()] = eid

    print(f"Saved entities. Saving {len(analysis_result.get('relationships', []))} relationships...")

    # Save Relationships
    rel_count = 0
    for rel in analysis_result.get("relationships", []):
        src_name = rel["source"].lower()
        tgt_name = rel["target"].lower()

        src_id = saved_entity_map.get(src_name)
        tgt_id = saved_entity_map.get(tgt_name)

        if not src_id:
            src_id = save_entity(rel["source"], rel.get("source_type", "entity"), investigation_id)
            saved_entity_map[src_name] = src_id

        if not tgt_id:
            tgt_id = save_entity(rel["target"], rel.get("target_type", "entity"), investigation_id)
            saved_entity_map[tgt_name] = tgt_id

        if src_id and tgt_id and src_id != tgt_id:
            save_relationship(
                source_entity_id=src_id,
                relationship_type=rel["relationship"],
                target_entity_id=tgt_id,
                source_id=rel.get("source_id"),
                evidence=rel.get("evidence", ""),
                confidence=rel.get("confidence", 0.8),
                investigation_id=investigation_id
            )
            rel_count += 1

    log_audit(
        investigation_id,
        "CONTROLLED_INGESTION_COMPLETED",
        f"Ingested {len(ingested_sources)} sources, extracted {len(saved_entity_map)} entities and {rel_count} relationships."
    )

    print(f"Ingestion complete: {len(ingested_sources)} sources, {len(saved_entity_map)} entities, {rel_count} relationships.")
    return len(ingested_sources)


if __name__ == "__main__":
    ingest_curated_corpus(investigation_id=1)
