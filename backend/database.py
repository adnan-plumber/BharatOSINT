import sqlite3
from datetime import datetime


DB_NAME = "bharatosint.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():

    conn = get_connection()
    cursor = conn.cursor()

    # -----------------------------
    # SOURCES / ARTICLES
    # -----------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            url TEXT UNIQUE,
            domain TEXT,
            snippet TEXT,
            content TEXT,
            collected_at TEXT
        )
    """)

    # -----------------------------
    # ENTITIES
    # -----------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            entity_type TEXT,
            UNIQUE(name, entity_type)
        )
    """)

    # -----------------------------
    # RELATIONSHIPS
    # -----------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_entity_id INTEGER,
            relationship_type TEXT,
            target_entity_id INTEGER,
            source_id INTEGER,
            evidence TEXT,
            FOREIGN KEY(source_entity_id) REFERENCES entities(id),
            FOREIGN KEY(target_entity_id) REFERENCES entities(id),
            FOREIGN KEY(source_id) REFERENCES sources(id)
        )
    """)

    conn.commit()
    conn.close()


def save_source(title, url, domain, snippet, content):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO sources
        (title, url, domain, snippet, content, collected_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        title,
        url,
        domain,
        snippet,
        content,
        datetime.utcnow().isoformat()
    ))

    conn.commit()

    source_id = cursor.execute(
        "SELECT id FROM sources WHERE url = ?",
        (url,)
    ).fetchone()["id"]

    conn.close()

    return source_id


def save_entity(name, entity_type):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO entities
        (name, entity_type)
        VALUES (?, ?)
    """, (name, entity_type))

    conn.commit()

    entity_id = cursor.execute("""
        SELECT id
        FROM entities
        WHERE name = ? AND entity_type = ?
    """, (name, entity_type)).fetchone()["id"]

    conn.close()

    return entity_id


def save_relationship(
    source_entity_id,
    relationship_type,
    target_entity_id,
    source_id,
    evidence
):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO relationships
        (
            source_entity_id,
            relationship_type,
            target_entity_id,
            source_id,
            evidence
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        source_entity_id,
        relationship_type,
        target_entity_id,
        source_id,
        evidence
    ))

    conn.commit()
    conn.close()