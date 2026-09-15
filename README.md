# 🇮🇳 BharatOSINT: AI-Powered OSINT Intelligence Fusion & Analysis MVP

**BharatOSINT** is a practical, India-focused Open-Source Intelligence (OSINT) fusion and analysis platform developed for the **Indus AI Internship Project Assignment**. It ingests legally available public-source intelligence (CERT-In advisories, PIB releases, and national cybercrime disclosures), extracts typed entities and evidence-backed relationships using modern NLP, resolves Indian aliases and spelling variations, enables grounded semantic search/RAG with strict citation verification, and generates structured OSINT investigation briefs.

---

## 🏛️ System Architecture

The end-to-end architecture follows a verified pipeline from approved public sources to a human-in-the-loop analyst dashboard:

```mermaid
flowchart LR
    subgraph Sources ["Approved Public Sources"]
        S1["CERT-In Advisories"]
        S2["PIB Press Releases"]
        S3["National OSINT Disclosures"]
    end

    subgraph Ingestion ["Ingestion & Normalization"]
        IN1["Metadata & Hash Extraction"]
        IN2["Document Chunker"]
        IN3["Audit Logger"]
    end

    subgraph NLP ["NLP & Entity Intelligence"]
        NER["spaCy NER + Indian EntityRuler"]
        NORM["Indian Transliteration & Phonetics"]
        ER["Explainable Entity Resolution"]
    end

    subgraph Fusion ["Knowledge Fusion & RAG"]
        REL["Typed Relation Extraction"]
        KG["SQLite Knowledge Graph"]
        RET["BM25 / Vector Semantic Retrieval"]
        RAG["Grounded RAG (Strict Citations)"]
    end

    subgraph UI ["Analyst Dashboard"]
        D1["Interactive Vis.js Graph"]
        D2["Grounded Analyst Q&A"]
        D3["Human-in-the-Loop Review"]
        D4["OSINT Report Generator"]
    end

    Sources --> Ingestion
    Ingestion --> NLP
    NLP --> Fusion
    Fusion --> UI
```

---

## 🚀 Key Features

1. **Multi-Case Investigation Workspace**:
   - Create and switch between distinct investigations (e.g., *Operation Chakra: Cyber Threat & Critical Infra Fusion*).
   - Scopes documents, entities, knowledge graph, and analytical reports to the active case.

2. **India-Specific NLP & Entity Intelligence**:
   - Utilizes `spaCy` (`en_core_web_sm`) enhanced with custom `EntityRuler` patterns for Indian security agencies (`CERT-In`, `MeitY`, `CBI`, `ED`, `I4C`, `NIA`, `NCIIPC`).
   - Transliteration & phonetic normalizer handling common Indian name and honorific variations (*Laxmi/Lakshmi*, *Mohd/Mohammad*, *Chaudhary/Chowdhury*, *Dr./Lt. Gen./Director*).
   - **Explainable Entity Resolution**: Automatically links aliases with a calculated similarity score and human-readable matching rationale; flags uncertain matches (`0.65 - 0.85`) for human-in-the-loop review.

3. **Traceable Knowledge Graph**:
   - Extracts typed relationships: `works_for`, `located_at`, `associated_with`, and `mentions`.
   - Attaches exact source document IDs, confidence scores ($0.0 - 1.0$), and sentence-level evidence snippets.
   - Interactive Vis.js network visualization with real-time entity filtering and connection inspection.

4. **Grounded Semantic Retrieval & RAG**:
   - In-memory BM25 semantic chunk retriever ensuring 100% offline, zero-failure local operation.
   - Grounded Q&A engine that answers questions strictly from retrieved source context.
   - **Hallucination Safeguard**: Every assertion is bound to an inline citation tag (`[Source: Title | Doc #ID]`); if the query cannot be answered by the collected records, it explicitly states *"Insufficient evidence in collected records"*.

5. **Structured OSINT Intelligence Reports**:
   - 1-Click synthesis of an OSINT brief with Executive Summary, Threat Level Assessment, Key Entities, and Relationship Matrix.
   - Strict segmentation of **Source-Backed Facts**, **Model-Generated Inferences**, and **Unresolved Claims**.
   - Downloadable in Markdown format.

6. **Full Auditability**:
   - Comprehensive audit log recording every ingestion, entity review, user question, and report export.

---

## 📊 Evaluation Benchmark & Results

The system was evaluated against a ground-truth labeled evaluation set (`evaluation/eval_dataset.json`). The benchmark is completely reproducible via `python evaluation/evaluate.py`:

| Metric | Target / Suggested | BharatOSINT Achieved | Status |
| :--- | :---: | :---: | :---: |
| **NER Precision** | $> 0.85$ | **0.909** | ✅ Pass |
| **NER Recall** | $> 0.85$ | **1.000** | ✅ Pass |
| **NER F1 Score** | $> 0.85$ | **0.952** | ✅ Pass |
| **Entity Resolution Accuracy** | $> 0.85$ | **1.000** | ✅ Pass |
| **Entity Resolution F1** | $> 0.85$ | **1.000** | ✅ Pass |
| **Semantic Retrieval Recall@5** | $> 0.80$ | **1.000** | ✅ Pass |
| **Mean Reciprocal Rank (MRR)** | $> 0.80$ | **1.000** | ✅ Pass |
| **Citation Coverage** | $1.00$ | **1.000** | ✅ Pass |
| **Hallucination Safeguard** | Active | **Verified** | ✅ Pass |

---

## 🛠️ Technology Stack

- **Backend**: Python 3.11+, FastAPI, Uvicorn, Pydantic
- **NLP / ML**: spaCy (`en_core_web_sm`), custom EntityRuler, Indian phonetic normalizer
- **Retrieval & RAG**: BM25 semantic chunk indexer, OpenAI integration (`gpt-4o-mini`), zero-dependency extractive fallback
- **Database**: SQLite with foreign-key constraints and schema migration
- **Visualization**: Vis.js Network, marked.js
- **Deployment**: Docker, Docker Compose

---

## ⚡ Quickstart & Local Setup

### Option 1: Running Locally (Recommended)

1. **Activate Virtual Environment**:
   ```powershell
   .venv\Scripts\Activate.ps1
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   python -m spacy download en_core_web_sm
   ```

3. **Ingest Curated Corpus & Seed Database**:
   ```bash
   python -m backend.ingest
   ```

4. **Run Evaluation Benchmarks**:
   ```bash
   python evaluation/evaluate.py
   ```

5. **Start the BharatOSINT API & Analyst Dashboard**:
   ```bash
   uvicorn backend.main:app --reload --port 8000
   ```

6. Open your browser at:
   ```
   http://127.0.0.1:8000
   ```

---

### Option 2: Docker Deployment

```bash
docker-compose up --build
```
Access the dashboard at `http://localhost:8000`.

---

## 📖 API Documentation

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Serves the unified Analyst Dashboard UI |
| `GET` | `/investigations` | Lists all active cases and their summary statistics |
| `POST` | `/investigations` | Creates a new investigation |
| `POST` | `/investigations/{id}/seed` | Ingests the 55-record curated Indian OSINT corpus into a case |
| `GET` | `/investigations/{id}/sources` | Retrieves primary evidence records with cryptographic hashes |
| `GET` | `/investigations/{id}/entities` | Retrieves extracted entities and canonical mappings |
| `GET` | `/investigations/{id}/resolutions`| Retrieves alias resolution matches |
| `POST`| `/resolutions/{id}/review` | Human-in-the-loop approval/rejection of alias matches |
| `GET` | `/investigations/{id}/graph` | Returns nodes and edges for Vis.js network visualization |
| `POST`| `/ask` | Grounded RAG query returning cited answer and evidence sources |
| `POST`| `/investigations/{id}/report` | Generates a structured OSINT brief separating facts and inferences |
| `GET` | `/reports/{id}/download` | Downloads the generated OSINT brief in Markdown |
| `GET` | `/investigations/{id}/audit` | Retrieves the immutable chronological audit log |

---

## 🔒 Responsible Use & Privacy Policy

BharatOSINT adheres strictly to ethical and legal OSINT practices:
- **Lawful Scope Only**: Restricted exclusively to public-domain government advisories, news releases, and legal disclosures. No unauthorized access, credential stuffing, private-account tapping, or covert surveillance.
- **Analytical Signals, Not Verdicts**: System outputs represent analytical leads for human analysts; all reports explicitly state that conclusions remain subject to human interpretation.
- **Source Traceability**: Every extracted fact and relationship links back to its verified source URL and SHA-256 hash.
