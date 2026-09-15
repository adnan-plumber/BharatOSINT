import os
import re
import hashlib
from datetime import datetime
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

from backend.database import (
    initialize_database,
    get_connection,
    create_investigation,
    get_investigations,
    get_investigation,
    save_source,
    save_entity,
    save_entity_resolution,
    get_entity_resolutions,
    update_resolution_status,
    save_relationship,
    save_report,
    get_reports,
    get_report,
    log_audit,
    get_audit_logs
)
from backend.analysis import analyze_articles
from backend.rag import SemanticRetriever, generate_grounded_answer
from backend.reporting import generate_investigation_report
from backend.ingest import ingest_curated_corpus

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

app = FastAPI(
    title="BharatOSINT",
    description="AI-Powered OSINT Intelligence Fusion & Analysis MVP (Indus AI)",
    version="2.0.0"
)

# Initialize DB on startup
initialize_database()

# Serve static files
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# -----------------------------
# PYDANTIC SCHEMAS
# -----------------------------

class InvestigationCreate(BaseModel):
    title: str
    description: Optional[str] = ""

class SearchRequest(BaseModel):
    query: str
    investigation_id: Optional[int] = 1

class QuestionRequest(BaseModel):
    query: str
    investigation_id: Optional[int] = 1
    top_k: Optional[int] = 5

class SourceCreate(BaseModel):
    title: str
    url: str
    domain: Optional[str] = ""
    author: Optional[str] = ""
    publication_date: Optional[str] = ""
    snippet: Optional[str] = ""
    content: str
    investigation_id: Optional[int] = 1

class ResolutionReview(BaseModel):
    status: str  # 'approved' or 'rejected'


# -----------------------------
# ROOT & DASHBOARD UI
# -----------------------------

@app.get("/")
def root():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {
        "project": "BharatOSINT",
        "status": "running",
        "message": "BharatOSINT Intelligence Fusion API v2.0 is active."
    }

@app.get("/health")
def health():
    return {"status": "healthy", "service": "BharatOSINT API v2.0"}

@app.get("/graph-ui")
def graph_ui():
    graph_path = os.path.join(STATIC_DIR, "graph.html")
    return FileResponse(graph_path)


# -----------------------------
# INVESTIGATION / CASE WORKSPACE
# -----------------------------

@app.get("/investigations")
def list_investigations():
    return {
        "status": "success",
        "investigations": get_investigations()
    }

@app.post("/investigations")
def create_new_investigation(req: InvestigationCreate):
    if not req.title.strip():
        raise HTTPException(status_code=400, detail="Title cannot be empty")
    inv_id = create_investigation(req.title.strip(), req.description.strip())
    return {
        "status": "success",
        "investigation_id": inv_id,
        "title": req.title.strip(),
        "message": f"Investigation #{inv_id} created successfully."
    }

@app.get("/investigations/{inv_id}")
def get_investigation_details(inv_id: int):
    inv = get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return {"status": "success", "investigation": inv}


# -----------------------------
# DATA INGESTION & SOURCES
# -----------------------------

@app.post("/investigations/{inv_id}/seed")
def seed_investigation_data(inv_id: int):
    """Populates the specified investigation with the curated 55-record Indian OSINT dataset."""
    inv = get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    count = ingest_curated_corpus(investigation_id=inv_id)
    return {
        "status": "success",
        "investigation_id": inv_id,
        "sources_ingested": count,
        "message": f"Successfully ingested {count} curated documents into Investigation #{inv_id}."
    }

@app.get("/investigations/{inv_id}/sources")
def get_investigation_sources(inv_id: int):
    conn = get_connection()
    rows = conn.execute("""
        SELECT id, title, url, domain, author, publication_date, snippet, doc_hash, collected_at
        FROM sources
        WHERE investigation_id = ?
        ORDER BY id DESC
    """, (inv_id,)).fetchall()
    conn.close()
    return {
        "status": "success",
        "total_sources": len(rows),
        "sources": [dict(r) for r in rows]
    }

@app.get("/sources/{source_id}")
def get_single_source(source_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Source not found")
    return {"status": "success", "source": dict(row)}

@app.post("/sources")
def add_custom_source(req: SourceCreate):
    source_id = save_source(
        title=req.title,
        url=req.url,
        domain=req.domain,
        author=req.author,
        publication_date=req.publication_date,
        snippet=req.snippet,
        content=req.content,
        investigation_id=req.investigation_id
    )
    return {"status": "success", "source_id": source_id}


# -----------------------------
# ENTITIES & HUMAN-IN-THE-LOOP RESOLUTION
# -----------------------------

@app.get("/investigations/{inv_id}/entities")
def get_investigation_entities(inv_id: int):
    conn = get_connection()
    rows = conn.execute("""
        SELECT id, name, entity_type, is_canonical, canonical_id
        FROM entities
        WHERE investigation_id = ?
        ORDER BY entity_type, name
    """, (inv_id,)).fetchall()
    conn.close()
    return {
        "status": "success",
        "total_entities": len(rows),
        "entities": [dict(r) for r in rows]
    }

@app.get("/investigations/{inv_id}/resolutions")
def list_resolutions(inv_id: int):
    resolutions = get_entity_resolutions(inv_id)
    return {
        "status": "success",
        "total_resolutions": len(resolutions),
        "resolutions": resolutions
    }

@app.post("/resolutions/{res_id}/review")
def review_resolution(res_id: int, review: ResolutionReview):
    """Allows an analyst to confirm or reject an automated entity resolution match."""
    if review.status not in ["approved", "rejected"]:
        raise HTTPException(status_code=400, detail="Status must be 'approved' or 'rejected'")
    update_resolution_status(res_id, review.status)
    log_audit(1, "RESOLUTION_REVIEWED", f"Analyst updated resolution ID {res_id} to '{review.status}'")
    return {"status": "success", "message": f"Resolution #{res_id} set to '{review.status}'"}


# -----------------------------
# KNOWLEDGE GRAPH
# -----------------------------

@app.get("/investigations/{inv_id}/graph")
def get_investigation_graph(inv_id: int):
    conn = get_connection()
    
    # Nodes
    entity_rows = conn.execute("""
        SELECT id, name, entity_type
        FROM entities
        WHERE investigation_id = ?
        ORDER BY id
    """, (inv_id,)).fetchall()

    nodes = []
    for ent in entity_rows:
        nodes.append({
            "id": ent["id"],
            "label": ent["name"],
            "type": ent["entity_type"]
        })

    # Edges
    rel_rows = conn.execute("""
        SELECT r.id, r.source_entity_id, r.relationship_type, r.target_entity_id,
               r.source_id, r.evidence, r.confidence, s.title as doc_title
        FROM relationships r
        LEFT JOIN sources s ON r.source_id = s.id
        WHERE r.investigation_id = ?
        ORDER BY r.id
    """, (inv_id,)).fetchall()

    edges = []
    for r in rel_rows:
        edges.append({
            "id": r["id"],
            "source": r["source_entity_id"],
            "target": r["target_entity_id"],
            "label": r["relationship_type"],
            "source_id": r["source_id"],
            "evidence": r["evidence"] or "",
            "confidence": r["confidence"] or 1.0,
            "doc_title": r["doc_title"] or ""
        })

    conn.close()

    return {
        "status": "success",
        "investigation_id": inv_id,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "nodes": nodes,
        "edges": edges
    }


# -----------------------------
# SEMANTIC RETRIEVAL & GROUNDED RAG
# -----------------------------

@app.post("/ask")
def ask_question(request: QuestionRequest):
    """
    Grounded RAG endpoint:
    Performs semantic BM25 retrieval over sources and generates an evidence-backed
    answer with strict inline source citations [Source: Title | Doc #ID].
    Guarantees hallucination safeguard with 'Insufficient evidence' check.
    """
    query = request.query.strip()
    inv_id = request.investigation_id or 1

    if not query:
        raise HTTPException(status_code=400, detail="Question cannot be empty")

    conn = get_connection()
    sources = [dict(r) for r in conn.execute(
        "SELECT id, title, url, domain, content FROM sources WHERE investigation_id = ?",
        (inv_id,)
    ).fetchall()]
    conn.close()

    if not sources:
        # Fallback to any sources
        conn = get_connection()
        sources = [dict(r) for r in conn.execute(
            "SELECT id, title, url, domain, content FROM sources LIMIT 100"
        ).fetchall()]
        conn.close()

    retriever = SemanticRetriever()
    retriever.index_documents(sources)
    retrieved_chunks = retriever.retrieve(query, top_k=request.top_k or 5)

    answer_obj = generate_grounded_answer(query, retrieved_chunks)

    log_audit(inv_id, "ANALYST_QUERY", f"Asked: '{query}' (Grounded: {answer_obj['grounded']}, Citations: {len(answer_obj['citations'])})")

    return {
        "status": "success",
        "query": query,
        "investigation_id": inv_id,
        "answer": answer_obj["answer"],
        "citations": answer_obj["citations"],
        "citation_coverage": answer_obj.get("citation_coverage", 0.0),
        "grounded": answer_obj["grounded"],
        "mode": answer_obj.get("mode", "extractive_grounded"),
        "evidence_sources": answer_obj.get("sources_used", [])
    }


# -----------------------------
# OSINT REPORT GENERATION
# -----------------------------

@app.post("/investigations/{inv_id}/report")
def create_report(inv_id: int):
    """Generates an evidence-backed structured OSINT brief separating facts, inferences, and unresolved claims."""
    res = generate_investigation_report(inv_id)
    if res.get("status") == "error":
        raise HTTPException(status_code=404, detail=res.get("message"))
    return res

@app.get("/investigations/{inv_id}/reports")
def list_investigation_reports(inv_id: int):
    reports = get_reports(inv_id)
    return {
        "status": "success",
        "investigation_id": inv_id,
        "reports": reports
    }

@app.get("/reports/{report_id}")
def view_report(report_id: int):
    rep = get_report(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"status": "success", "report": rep}

@app.get("/reports/{report_id}/download")
def download_report(report_id: int):
    rep = get_report(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found")
    filename = f"OSINT_Report_Inv_{rep['investigation_id']}_{report_id}.md"
    return Response(
        content=rep["content_markdown"],
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# -----------------------------
# AUDIT LOGS
# -----------------------------

@app.get("/investigations/{inv_id}/audit")
def view_audit_trail(inv_id: int, limit: int = 50):
    logs = get_audit_logs(investigation_id=inv_id, limit=limit)
    return {
        "status": "success",
        "investigation_id": inv_id,
        "total_events": len(logs),
        "audit_logs": logs
    }


# -----------------------------
# LEGACY BACKWARDS-COMPATIBILITY ENDPOINTS
# -----------------------------

@app.get("/dashboard")
def dashboard():
    conn = get_connection()
    total_sources = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
    total_entities = conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
    total_relationships = conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0]
    entity_types = conn.execute("SELECT entity_type, COUNT(*) as count FROM entities GROUP BY entity_type ORDER BY count DESC").fetchall()
    relationship_types = conn.execute("SELECT relationship_type, COUNT(*) as count FROM relationships GROUP BY relationship_type ORDER BY count DESC").fetchall()
    conn.close()

    return {
        "status": "success",
        "total_sources": total_sources,
        "total_entities": total_entities,
        "total_relationships": total_relationships,
        "entity_types": [{"type": r["entity_type"], "count": r["count"]} for r in entity_types],
        "relationship_types": [{"type": r["relationship_type"], "count": r["count"]} for r in relationship_types]
    }

@app.get("/sources")
def get_legacy_sources():
    conn = get_connection()
    rows = conn.execute("SELECT id, title, url, domain, snippet, collected_at FROM sources ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return {"status": "success", "total_sources": len(rows), "sources": [dict(r) for r in rows]}

@app.get("/entities")
def get_legacy_entities():
    conn = get_connection()
    rows = conn.execute("SELECT id, name, entity_type FROM entities ORDER BY entity_type, name LIMIT 200").fetchall()
    conn.close()
    return {"status": "success", "total_entities": len(rows), "entities": [dict(r) for r in rows]}

@app.get("/relationships")
def get_legacy_relationships():
    conn = get_connection()
    rows = conn.execute("""
        SELECT r.id, se.name AS source, se.entity_type AS source_type,
               r.relationship_type, te.name AS target, te.entity_type AS target_type,
               r.source_id, r.evidence, r.confidence
        FROM relationships r
        LEFT JOIN entities se ON r.source_entity_id = se.id
        LEFT JOIN entities te ON r.target_entity_id = te.id
        ORDER BY r.id DESC LIMIT 200
    """).fetchall()
    conn.close()
    return {"status": "success", "total_relationships": len(rows), "relationships": [dict(r) for r in rows]}

@app.get("/graph")
def get_legacy_graph():
    return get_investigation_graph(1)