from dotenv import load_dotenv
import os
from fastapi.responses import FileResponse
import re
from backend.analysis import analyze_articles
from backend.database import (
    initialize_database,
    get_connection,
    save_source,
    save_entity,
    save_relationship
)
import sqlite3
from fastapi import FastAPI
from pydantic import BaseModel
from ddgs import DDGS
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from openai import OpenAI

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

app = FastAPI(
    title="BharatOSINT",
    description="AI-Powered OSINT Intelligence Fusion & Analysis MVP",
    version="1.0.0"
)

initialize_database()

class SearchRequest(BaseModel):
    query: str


def extract_article(url: str):
    """
    Fetch a webpage and extract readable text.
    """

    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/140.0 Safari/537.36"
            )
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=8
        )

        if response.status_code != 200:
            return {
                "status": "failed",
                "content": "",
                "error": f"HTTP {response.status_code}"
            }

        soup = BeautifulSoup(response.text, "html.parser")

        # Remove unnecessary elements
        for element in soup([
            "script",
            "style",
            "nav",
            "footer",
            "header",
            "aside",
            "form"
        ]):
            element.decompose()

        paragraphs = soup.find_all("p")

        text_parts = []

        for paragraph in paragraphs:
            text = paragraph.get_text(" ", strip=True)

            if len(text) > 40:
                text_parts.append(text)

        content = " ".join(text_parts)

        # Prevent extremely large responses
        content = content[:8000]

        domain = urlparse(url).netloc

        return {
            "status": "success",
            "domain": domain,
            "content": content
        }

    except Exception as e:
        return {
            "status": "failed",
            "content": "",
            "error": str(e)
        }


@app.get("/")
def root():
    return {
        "project": "BharatOSINT",
        "status": "running",
        "message": "BharatOSINT API is working"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }

@app.get("/dashboard")
def dashboard():

    conn = get_connection()
    cursor = conn.cursor()

    # Total sources
    total_sources = cursor.execute(
        "SELECT COUNT(*) FROM sources"
    ).fetchone()[0]

    # Total entities
    total_entities = cursor.execute(
        "SELECT COUNT(*) FROM entities"
    ).fetchone()[0]

    # Total relationships
    total_relationships = cursor.execute(
        "SELECT COUNT(*) FROM relationships"
    ).fetchone()[0]

    # Entity types
    entity_types = cursor.execute("""
        SELECT entity_type, COUNT(*) as count
        FROM entities
        GROUP BY entity_type
        ORDER BY count DESC
    """).fetchall()

    # Relationship types
    relationship_types = cursor.execute("""
        SELECT relationship_type, COUNT(*) as count
        FROM relationships
        GROUP BY relationship_type
        ORDER BY count DESC
    """).fetchall()

    conn.close()

    return {
        "status": "success",

        "total_sources": total_sources,

        "total_entities": total_entities,

        "total_relationships": total_relationships,

        "entity_types": [
            {
                "type": row["entity_type"],
                "count": row["count"]
            }
            for row in entity_types
        ],

        "relationship_types": [
            {
                "type": row["relationship_type"],
                "count": row["count"]
            }
            for row in relationship_types
        ]
    }


# =========================================
# SEARCH + OSINT ANALYSIS
# =========================================

@app.post("/search")
def search(request: SearchRequest):

    query = request.query.strip()

    if not query:
        return {
            "status": "error",
            "message": "Search query cannot be empty"
        }

    results = []

    try:

        # =====================================
        # STEP 1: WEB SEARCH
        # =====================================

        with DDGS() as ddgs:

            search_results = ddgs.text(
                query,
                region="in-en",
                safesearch="moderate",
                max_results=10
            )

            for item in search_results:

                title = item.get("title")
                url = item.get("href")
                snippet = item.get("body")

                if not url:
                    continue

                # =====================================
                # STEP 2: ARTICLE EXTRACTION
                # =====================================

                article = extract_article(url)

                # =====================================
                # STEP 3: SAVE SOURCE
                # =====================================

                source_id = save_source(
                    title=title,
                    url=url,
                    domain=article.get("domain"),
                    snippet=snippet,
                    content=article.get("content")
                )

                # =====================================
                # STEP 4: STORE RESULT
                # =====================================

                results.append({
                    "source_id": source_id,
                    "title": title,
                    "url": url,
                    "snippet": snippet,
                    "source": "Web Search",

                    "article": {
                        "status": article.get("status"),
                        "domain": article.get("domain"),
                        "content": article.get("content"),
                        "error": article.get("error")
                    }
                })

    except Exception as e:

        return {
            "query": query,
            "status": "error",
            "message": str(e)
        }

    # =====================================
    # STEP 5: BASIC ANALYSIS
    # =====================================

    successful_articles = sum(
        1
        for result in results
        if result["article"]["status"] == "success"
    )

    analysis = analyze_articles(results)

    # =====================================
    # STEP 6: SAVE ENTITIES
    # =====================================

    entity_ids = {}

    entities = analysis.get("entities", {})

    # -------------------------------------
    # PEOPLE
    # -------------------------------------

    for person in entities.get("people", []):

        entity_ids[("person", person)] = save_entity(
            person,
            "person"
        )

    # -------------------------------------
    # ORGANIZATIONS
    # -------------------------------------

    for organization in entities.get("organizations", []):

        entity_ids[("organization", organization)] = save_entity(
            organization,
            "organization"
        )

    # -------------------------------------
    # LOCATIONS
    # -------------------------------------

    for location in entities.get("locations", []):

        entity_ids[("location", location)] = save_entity(
            location,
            "location"
        )

    # -------------------------------------
    # DATES
    # -------------------------------------

    for date in entities.get("dates", []):

        entity_ids[("date", date)] = save_entity(
            date,
            "date"
        )

    # -------------------------------------
    # THREAT INDICATORS
    # -------------------------------------

    for threat in analysis.get("threat_indicators", []):

        entity_ids[("threat", threat)] = save_entity(
            threat,
            "threat"
        )

    # -------------------------------------
    # EMAILS
    # -------------------------------------

    for email in analysis.get("emails", []):

        entity_ids[("email", email)] = save_entity(
            email,
            "email"
        )

    # -------------------------------------
    # URLS
    # -------------------------------------

    for url_value in analysis.get("urls", []):

        entity_ids[("url", url_value)] = save_entity(
            url_value,
            "url"
        )

    # =====================================
    # STEP 7: SAVE RELATIONSHIPS
    # =====================================

    relationships = analysis.get(
        "relationships",
        []
    )

    for relationship in relationships:

        source_name = relationship.get("source")
        target_name = relationship.get("target")

        relationship_type = relationship.get(
            "relationship",
            "associated_with"
        )

        source_entity = None
        target_entity = None

        # -------------------------------------
        # FIND ENTITY IDS
        # -------------------------------------

        for key, entity_id in entity_ids.items():

            entity_type, entity_name = key

            if entity_name == source_name:

                source_entity = entity_id

            if entity_name == target_name:

                target_entity = entity_id

        # -------------------------------------
        # ONLY SAVE VALID RELATIONSHIPS
        # -------------------------------------

        if source_entity and target_entity:

            source_id = None
            evidence = ""

            # =================================
            # FIND SOURCE ARTICLE
            # =================================

            for result in results:

                content = result.get(
                    "article",
                    {}
                ).get(
                    "content",
                    ""
                )

                if not content:
                    continue

                if (
                    source_name.lower() in content.lower()
                    and
                    target_name.lower() in content.lower()
                ):

                    source_id = result.get(
                        "source_id"
                    )

                    # =================================
                    # FIND EVIDENCE SENTENCE
                    # =================================

                    sentences = re.split(
                        r'(?<=[.!?])\s+',
                        content
                    )

                    for sentence in sentences:

                        if (
                            source_name.lower()
                            in sentence.lower()

                            and

                            target_name.lower()
                            in sentence.lower()
                        ):

                            evidence = sentence[:1000]

                            break

                    break

            # =================================
            # SAVE RELATIONSHIP
            # =================================

            if source_id:

                save_relationship(
                    source_entity_id=source_entity,
                    relationship_type=relationship_type,
                    target_entity_id=target_entity,
                    source_id=source_id,
                    evidence=evidence
                )

    # =========================================
    # STEP 8: FINAL RESPONSE
    # =========================================

    return {

        "query": query,

        "status": "success",

        "total_results": len(results),

        "articles_extracted": successful_articles,

        "results": results,

        "analysis": analysis

    }

@app.post("/ask")
def ask(request: SearchRequest):

    query = request.query.strip()

    if not query:
        return {
            "status": "error",
            "message": "Question cannot be empty"
        }

    conn = sqlite3.connect("bharatosint.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # =====================================
    # FIND RELEVANT SOURCES
    # =====================================

    rows = cursor.execute("""
        SELECT
            id,
            title,
            url,
            domain,
            content
        FROM sources
        WHERE
            content LIKE ?
            OR title LIKE ?
            OR snippet LIKE ?
        ORDER BY id DESC
        LIMIT 5
    """, (
        f"%{query}%",
        f"%{query}%",
        f"%{query}%"
    )).fetchall()

    conn.close()

    sources = []

    for row in rows:

        sources.append({
            "source_id": row["id"],
            "title": row["title"],
            "url": row["url"],
            "domain": row["domain"],
            "content": row["content"]
        })

    # =====================================
    # BUILD CONTEXT
    # =====================================

    context = []

    for source in sources:

        content = source.get("content") or ""

        context.append(
            f"TITLE: {source['title']}\n"
            f"SOURCE: {source['url']}\n"
            f"CONTENT:\n{content[:5000]}"
        )

    combined_context = "\n\n--- SOURCE ---\n\n".join(context)

    # =====================================
    # RESPONSE
    # =====================================

    return {

        "status": "success",

        "query": query,

        "sources_found": len(sources),

        "context": combined_context,

        "sources": [
            {
                "source_id": source["source_id"],
                "title": source["title"],
                "url": source["url"],
                "domain": source["domain"]
            }
            for source in sources
        ]

    }

@app.get("/sources")
def get_sources():

    conn = sqlite3.connect("bharatosint.db")
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    rows = cursor.execute("""
        SELECT
            id,
            title,
            url,
            domain,
            snippet,
            content,
            collected_at
        FROM sources
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return {
        "status": "success",
        "total_sources": len(rows),
        "sources": [dict(row) for row in rows]
    }

@app.get("/entities")
def get_entities():

    conn = sqlite3.connect("bharatosint.db")
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    rows = cursor.execute("""
        SELECT
            id,
            name,
            entity_type
        FROM entities
        ORDER BY entity_type, name
    """).fetchall()

    conn.close()

    return {
        "status": "success",
        "total_entities": len(rows),
        "entities": [dict(row) for row in rows]
    }

@app.get("/relationships")
def get_relationships():

    conn = sqlite3.connect("bharatosint.db")
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    rows = cursor.execute("""
        SELECT
            r.id,
            se.name AS source,
            se.entity_type AS source_type,
            r.relationship_type,
            te.name AS target,
            te.entity_type AS target_type,
            r.source_id,
            r.evidence
        FROM relationships r
        LEFT JOIN entities se
            ON r.source_entity_id = se.id
        LEFT JOIN entities te
            ON r.target_entity_id = te.id
        ORDER BY r.id DESC
    """).fetchall()

    conn.close()

    return {
        "status": "success",
        "total_relationships": len(rows),
        "relationships": [dict(row) for row in rows]
    }

@app.get("/graph")
def get_graph():

    conn = sqlite3.connect("bharatosint.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # -----------------------------
    # NODES
    # -----------------------------

    entity_rows = cursor.execute("""
        SELECT id, name, entity_type
        FROM entities
        ORDER BY id
    """).fetchall()

    nodes = []

    for entity in entity_rows:
        nodes.append({
            "id": entity["id"],
            "label": entity["name"],
            "type": entity["entity_type"]
        })

    # -----------------------------
    # EDGES
    # -----------------------------

    relationship_rows = cursor.execute("""
        SELECT
            id,
            source_entity_id,
            relationship_type,
            target_entity_id,
            source_id,
            evidence
        FROM relationships
        ORDER BY id
    """).fetchall()

    edges = []

    for relationship in relationship_rows:
        edges.append({
            "id": relationship["id"],
            "source": relationship["source_entity_id"],
            "target": relationship["target_entity_id"],
            "label": relationship["relationship_type"],
            "source_id": relationship["source_id"],
            "evidence": relationship["evidence"]
        })

    conn.close()

    return {
        "status": "success",
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "nodes": nodes,
        "edges": edges
    }

@app.get("/graph-ui")
def graph_ui():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    graph_path = os.path.join(base_dir, "static", "graph.html")

    return FileResponse(graph_path)