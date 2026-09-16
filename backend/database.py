import sqlite3
import os
import hashlib
from datetime import datetime

DB_NAME = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "bharatosint.db"
)


def get_connection():
    conn = sqlite3.connect(DB_NAME, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def _ensure_columns(cursor, table_name, expected_columns):
    """Safely adds missing columns to existing tables for backwards compatibility."""
    cursor.execute(f"PRAGMA table_info({table_name})")
    existing_cols = {row[1] for row in cursor.fetchall()}
    for col_name, col_type in expected_columns.items():
        if col_name not in existing_cols:
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    # -----------------------------
    # 1. INVESTIGATIONS / CASES
    # -----------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL
        )
    """)

    # -----------------------------
    # 2. SOURCES / ARTICLES
    # -----------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER DEFAULT 1,
            title TEXT,
            url TEXT UNIQUE,
            domain TEXT,
            author TEXT,
            publication_date TEXT,
            snippet TEXT,
            content TEXT,
            collected_at TEXT,
            doc_hash TEXT,
            FOREIGN KEY(investigation_id) REFERENCES investigations(id)
        )
    """)
    _ensure_columns(cursor, "sources", {
        "investigation_id": "INTEGER DEFAULT 1",
        "author": "TEXT",
        "publication_date": "TEXT",
        "doc_hash": "TEXT"
    })

    # -----------------------------
    # 3. ENTITIES
    # -----------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER DEFAULT 1,
            canonical_id INTEGER,
            name TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            is_canonical INTEGER DEFAULT 1,
            created_at TEXT,
            FOREIGN KEY(investigation_id) REFERENCES investigations(id),
            FOREIGN KEY(canonical_id) REFERENCES entities(id)
        )
    """)
    _ensure_columns(cursor, "entities", {
        "investigation_id": "INTEGER DEFAULT 1",
        "canonical_id": "INTEGER",
        "is_canonical": "INTEGER DEFAULT 1",
        "created_at": "TEXT"
    })

    # -----------------------------
    # 4. ENTITY RESOLUTIONS (Aliases & Match Scores)
    # -----------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS entity_resolutions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER DEFAULT 1,
            alias_name TEXT NOT NULL,
            canonical_entity_id INTEGER NOT NULL,
            match_score REAL NOT NULL,
            rationale TEXT,
            status TEXT DEFAULT 'auto_matched',
            created_at TEXT,
            FOREIGN KEY(investigation_id) REFERENCES investigations(id),
            FOREIGN KEY(canonical_entity_id) REFERENCES entities(id)
        )
    """)

    # -----------------------------
    # 5. RELATIONSHIPS
    # -----------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER DEFAULT 1,
            source_entity_id INTEGER NOT NULL,
            relationship_type TEXT NOT NULL,
            target_entity_id INTEGER NOT NULL,
            source_id INTEGER,
            evidence TEXT,
            confidence REAL DEFAULT 1.0,
            FOREIGN KEY(investigation_id) REFERENCES investigations(id),
            FOREIGN KEY(source_entity_id) REFERENCES entities(id),
            FOREIGN KEY(target_entity_id) REFERENCES entities(id),
            FOREIGN KEY(source_id) REFERENCES sources(id)
        )
    """)
    _ensure_columns(cursor, "relationships", {
        "investigation_id": "INTEGER DEFAULT 1",
        "confidence": "REAL DEFAULT 1.0"
    })

    # -----------------------------
    # 6. AUDIT LOGS
    # -----------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER DEFAULT 1,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(investigation_id) REFERENCES investigations(id)
        )
    """)

    # -----------------------------
    # 7. INVESTIGATION REPORTS
    # -----------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            summary TEXT,
            content_markdown TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(investigation_id) REFERENCES investigations(id)
        )
    """)

    # Ensure default investigation exists
    cursor.execute("SELECT id FROM investigations WHERE id = 1")
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO investigations (id, title, description, status, created_at)
            VALUES (1, 'Operation Chakra: Indian Cyber Threat & Critical Infra Fusion', 
                    'Primary intelligence workspace focusing on critical infrastructure advisories, digital arrest networks, and cyber threat campaigns in India.',
                    'active', ?)
        """, (datetime.utcnow().isoformat(),))

    # Update existing null investigation_ids
    cursor.execute("UPDATE sources SET investigation_id = 1 WHERE investigation_id IS NULL")
    cursor.execute("UPDATE entities SET investigation_id = 1 WHERE investigation_id IS NULL")
    cursor.execute("UPDATE relationships SET investigation_id = 1 WHERE investigation_id IS NULL")

    conn.commit()
    conn.close()


# -----------------------------
# INVESTIGATION HELPERS
# -----------------------------

def create_investigation(title: str, description: str = ""):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat()
    cursor.execute("""
        INSERT INTO investigations (title, description, status, created_at)
        VALUES (?, ?, 'active', ?)
    """, (title, description, now))
    inv_id = cursor.lastrowid
    conn.commit()
    conn.close()
    log_audit(inv_id, "INVESTIGATION_CREATED", f"Created investigation: {title}")
    return inv_id


def get_investigations():
    conn = get_connection()
    rows = conn.execute("""
        SELECT i.id, i.title, i.description, i.status, i.created_at,
               (SELECT COUNT(*) FROM sources WHERE investigation_id = i.id) as source_count,
               (SELECT COUNT(*) FROM entities WHERE investigation_id = i.id) as entity_count,
               (SELECT COUNT(*) FROM relationships WHERE investigation_id = i.id) as relationship_count
        FROM investigations i
        ORDER BY i.id ASC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_investigation(inv_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


# -----------------------------
# AUDIT LOG HELPERS
# -----------------------------

def log_audit(investigation_id: int, action: str, details: str = ""):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_logs (investigation_id, action, details, timestamp)
        VALUES (?, ?, ?, ?)
    """, (investigation_id, action, details, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


def get_audit_logs(investigation_id: int = None, limit: int = 50):
    conn = get_connection()
    if investigation_id:
        rows = conn.execute("""
            SELECT * FROM audit_logs
            WHERE investigation_id = ?
            ORDER BY id DESC LIMIT ?
        """, (investigation_id, limit)).fetchall()
    else:
        rows = conn.execute("""
            SELECT * FROM audit_logs
            ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# -----------------------------
# SOURCE HELPERS
# -----------------------------

def save_source(title, url, domain, snippet, content, author=None, publication_date=None, investigation_id=1, doc_hash=None):
    if not doc_hash and content:
        doc_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO sources
        (investigation_id, title, url, domain, author, publication_date, snippet, content, collected_at, doc_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        investigation_id,
        title,
        url,
        domain,
        author,
        publication_date or datetime.utcnow().strftime("%Y-%m-%d"),
        snippet,
        content,
        datetime.utcnow().isoformat(),
        doc_hash
    ))
    conn.commit()

    row = cursor.execute("SELECT id FROM sources WHERE url = ?", (url,)).fetchone()
    source_id = row["id"] if row else None
    conn.close()

    if source_id:
        log_audit(investigation_id, "SOURCE_INGESTED", f"Ingested source ID {source_id}: {title[:80]}")
    return source_id


# -----------------------------
# ENTITY & RESOLUTION HELPERS
# -----------------------------

def save_entity(name: str, entity_type: str, investigation_id: int = 1, canonical_id: int = None, is_canonical: int = 1):
    conn = get_connection()
    cursor = conn.cursor()

    # Check if exact entity already exists in this investigation
    existing = cursor.execute("""
        SELECT id, canonical_id FROM entities 
        WHERE name = ? AND entity_type = ? AND investigation_id = ?
    """, (name, entity_type, investigation_id)).fetchone()

    if existing:
        entity_id = existing["id"]
        conn.close()
        return entity_id

    now = datetime.utcnow().isoformat()
    cursor.execute("""
        INSERT INTO entities (investigation_id, canonical_id, name, entity_type, is_canonical, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (investigation_id, canonical_id, name, entity_type, is_canonical, now))
    entity_id = cursor.lastrowid

    # If canonical_id was None and is_canonical is True, point to self
    if is_canonical and canonical_id is None:
        cursor.execute("UPDATE entities SET canonical_id = ? WHERE id = ?", (entity_id, entity_id))

    conn.commit()
    conn.close()
    return entity_id


def save_entity_resolution(investigation_id: int, alias_name: str, canonical_entity_id: int, match_score: float, rationale: str, status: str = "auto_matched"):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat()

    cursor.execute("""
        INSERT INTO entity_resolutions (investigation_id, alias_name, canonical_entity_id, match_score, rationale, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (investigation_id, alias_name, canonical_entity_id, match_score, rationale, status, now))
    conn.commit()
    conn.close()


def get_entity_resolutions(investigation_id: int = None):
    conn = get_connection()
    query = """
        SELECT er.*, e.name as canonical_name, e.entity_type
        FROM entity_resolutions er
        JOIN entities e ON er.canonical_entity_id = e.id
    """
    params = []
    if investigation_id:
        query += " WHERE er.investigation_id = ?"
        params.append(investigation_id)
    query += " ORDER BY er.id DESC"

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_resolution_status(resolution_id: int, new_status: str):
    conn = get_connection()
    conn.execute("UPDATE entity_resolutions SET status = ? WHERE id = ?", (new_status, resolution_id))
    conn.commit()
    conn.close()


# -----------------------------
# RELATIONSHIP HELPERS
# -----------------------------

def save_relationship(
    source_entity_id: int,
    relationship_type: str,
    target_entity_id: int,
    source_id: int,
    evidence: str,
    confidence: float = 1.0,
    investigation_id: int = 1
):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO relationships
        (investigation_id, source_entity_id, relationship_type, target_entity_id, source_id, evidence, confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        investigation_id,
        source_entity_id,
        relationship_type,
        target_entity_id,
        source_id,
        evidence,
        confidence
    ))

    rel_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return rel_id


# -----------------------------
# REPORT HELPERS
# -----------------------------

def save_report(investigation_id: int, title: str, summary: str, content_markdown: str):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat()
    cursor.execute("""
        INSERT INTO reports (investigation_id, title, summary, content_markdown, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (investigation_id, title, summary, content_markdown, now))
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    log_audit(investigation_id, "REPORT_GENERATED", f"Generated report ID {report_id}: {title}")
    return report_id


def get_reports(investigation_id: int = None):
    conn = get_connection()
    if investigation_id:
        rows = conn.execute("""
            SELECT id, investigation_id, title, summary, created_at
            FROM reports WHERE investigation_id = ? ORDER BY id DESC
        """, (investigation_id,)).fetchall()
    else:
        rows = conn.execute("""
            SELECT id, investigation_id, title, summary, created_at
            FROM reports ORDER BY id DESC
        """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_report(report_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    conn.close()
    return dict(row) if row else None