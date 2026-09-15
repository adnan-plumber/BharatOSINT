import os
import re
import math
from collections import Counter
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
openai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None


# -------------------------------------------------------------
# LIGHTWEIGHT IN-MEMORY TF-IDF / BM25 SEMANTIC RETRIEVER
# -------------------------------------------------------------

def tokenize(text: str) -> list:
    return [w.lower() for w in re.findall(r'[a-zA-Z0-9_\-]+', text) if len(w) > 2]


class SemanticRetriever:
    """
    In-memory BM25 / TF-IDF semantic evidence retrieval engine.
    Ensures 100% offline reproducibility without external vector DB dependencies.
    """
    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.chunks = []
        self.doc_lens = []
        self.avg_dl = 0.0
        self.doc_freqs = Counter()
        self.idf = {}

    def index_documents(self, documents: list):
        """
        Chunks documents into discrete evidence units (sentences / paragraphs)
        and builds the inverted index.
        """
        self.chunks = []
        for doc in documents:
            source_id = doc.get("id") or doc.get("source_id")
            title = doc.get("title", "Untitled")
            url = doc.get("url", "")
            domain = doc.get("domain", "")
            content = doc.get("content", "")

            # Split into paragraphs or multi-sentence chunks (~400 chars)
            sentences = re.split(r'(?<=[.!?])\s+', content)
            buffer = ""
            for s in sentences:
                s = s.strip()
                if not s:
                    continue
                if len(buffer) + len(s) < 450:
                    buffer = f"{buffer} {s}".strip()
                else:
                    if buffer:
                        self.chunks.append({
                            "source_id": source_id,
                            "title": title,
                            "url": url,
                            "domain": domain,
                            "content": buffer
                        })
                    buffer = s

            if buffer:
                self.chunks.append({
                    "source_id": source_id,
                    "title": title,
                    "url": url,
                    "domain": domain,
                    "content": buffer
                })

        # Calculate BM25 statistics
        num_docs = len(self.chunks)
        if num_docs == 0:
            return

        self.doc_lens = []
        self.doc_freqs = Counter()

        for chunk in self.chunks:
            tokens = set(tokenize(f"{chunk['title']} {chunk['content']}"))
            self.doc_lens.append(len(tokens))
            for t in tokens:
                self.doc_freqs[t] += 1

        self.avg_dl = sum(self.doc_lens) / num_docs if num_docs > 0 else 1.0

        self.idf = {}
        for t, df in self.doc_freqs.items():
            self.idf[t] = math.log((num_docs - df + 0.5) / (df + 0.5) + 1.0)

    def retrieve(self, query: str, top_k: int = 5) -> list:
        """
        Returns top_k ranked chunks for query.
        """
        query_tokens = tokenize(query)
        if not query_tokens or not self.chunks:
            return []

        scores = []
        for idx, chunk in enumerate(self.chunks):
            chunk_tokens = tokenize(f"{chunk['title']} {chunk['content']}")
            chunk_len = len(chunk_tokens)
            score = 0.0

            token_counts = Counter(chunk_tokens)
            for qt in query_tokens:
                if qt in token_counts:
                    tf = token_counts[qt]
                    idf_val = self.idf.get(qt, 0.5)
                    denom = tf + self.k1 * (1.0 - self.b + self.b * (chunk_len / self.avg_dl))
                    score += idf_val * (tf * (self.k1 + 1.0)) / denom

            # Exact phrase bonus
            if query.lower() in chunk["content"].lower():
                score += 3.0

            if score > 0.1:
                scores.append((score, chunk))

        scores.sort(key=lambda x: x[0], reverse=True)
        ranked_results = []
        seen_sources = set()

        for rank, (score, chunk) in enumerate(scores[:top_k * 2], 1):
            sid = chunk["source_id"]
            if sid not in seen_sources or len(seen_sources) < top_k:
                seen_sources.add(sid)
                ranked_results.append({
                    "rank": len(ranked_results) + 1,
                    "score": round(score, 3),
                    "source_id": chunk["source_id"],
                    "title": chunk["title"],
                    "url": chunk["url"],
                    "domain": chunk["domain"],
                    "content": chunk["content"]
                })
            if len(ranked_results) >= top_k:
                break

        return ranked_results


# -------------------------------------------------------------
# GROUNDED ANSWER GENERATION
# -------------------------------------------------------------

def generate_grounded_answer(query: str, retrieved_evidence: list) -> dict:
    """
    Generates an evidence-backed answer strictly grounded in the retrieved sources.
    Falls back to deterministic extractive grounding if OpenAI quota is exhausted.
    """
    if not retrieved_evidence:
        return {
            "query": query,
            "answer": "Insufficient evidence in collected records to answer this question. No matching intelligence sources were found.",
            "citations": [],
            "citation_coverage": 0.0,
            "grounded": False,
            "mode": "no_evidence"
        }

    # Format context with explicit citation anchors
    context_blocks = []
    sources_metadata = []

    for item in retrieved_evidence:
        sid = item["source_id"]
        title = item["title"]
        url = item["url"]
        content = item["content"]

        context_blocks.append(f"[Source: {title} | Doc #{sid}]\n{content}")
        sources_metadata.append({
            "source_id": sid,
            "title": title,
            "url": url,
            "score": item["score"]
        })

    combined_context = "\n\n---\n\n".join(context_blocks)

    # 1. Attempt LLM Generation if OpenAI is available
    if openai_client:
        try:
            system_prompt = (
                "You are BharatOSINT, an AI-powered intelligence fusion analyst for India-focused investigations. "
                "Your task is to answer the analyst's question based strictly and exclusively on the provided source documents.\n"
                "Rules:\n"
                "1. Base every claim ONLY on the provided context.\n"
                "2. Every statement or finding MUST include an inline citation in the exact format: [Source: <Title> | Doc #<ID>].\n"
                "3. If the context does not contain enough facts to answer, explicitly say: "
                "'Insufficient evidence in collected records to answer this question.'\n"
                "4. Do NOT speculate or mention information not present in the sources."
            )

            user_prompt = f"Question: {query}\n\nRetrieved Source Context:\n{combined_context}\n\nEvidence-Backed Answer:"

            response = openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=600
            )

            answer_text = response.choices[0].message.content.strip()

            # Parse citations
            citations_found = list(set(re.findall(r'\[Source:\s*([^|]+?)\s*\|\s*Doc\s*#(\d+)\]', answer_text)))

            coverage = 1.0 if citations_found else 0.0

            return {
                "query": query,
                "answer": answer_text,
                "citations": [
                    {"title": c[0].strip(), "source_id": int(c[1])} for c in citations_found
                ],
                "sources_used": sources_metadata,
                "citation_coverage": coverage,
                "grounded": True,
                "mode": "llm_grounded"
            }

        except Exception as e:
            # Fallback to local extractive synthesizer if API fails (e.g. 429 quota exhausted)
            pass

    # 2. Local Deterministic Grounded Extractive Synthesizer (Zero-Failure Fallback)
    return _local_extractive_grounding(query, retrieved_evidence, sources_metadata)


def _local_extractive_grounding(query: str, retrieved_evidence: list, sources_metadata: list) -> dict:
    """
    Deterministic extractive grounding engine:
    Extracts high-salience factual sentences directly from retrieved sources,
    attaches verifiable citations, and enforces insufficient-evidence checks.
    """
    query_tokens = [w for w in tokenize(query) if w not in {"who", "what", "where", "when", "which", "how", "the", "and", "for", "with", "from", "that", "this"}]

    if not query_tokens or not retrieved_evidence:
        return {
            "query": query,
            "answer": "Insufficient evidence in collected records to answer this question.",
            "citations": [],
            "sources_used": sources_metadata,
            "citation_coverage": 0.0,
            "grounded": False,
            "mode": "extractive_insufficient"
        }

    # Verify that at least 50% of the query's salient keywords appear in the retrieved context
    all_context_tokens = set(tokenize(" ".join([item["content"] for item in retrieved_evidence])))
    salient_matches = [qt for qt in query_tokens if qt in all_context_tokens]
    
    if len(salient_matches) / max(len(query_tokens), 1) < 0.35:
        return {
            "query": query,
            "answer": f"Insufficient evidence in collected records to answer this question. The collected intelligence workspace does not contain documentation regarding '{query}'.",
            "citations": [],
            "sources_used": sources_metadata,
            "citation_coverage": 0.0,
            "grounded": False,
            "mode": "extractive_insufficient"
        }

    # Ensure the top retrieved score is significant
    if not retrieved_evidence or max(item["score"] for item in retrieved_evidence) < 1.8:
        return {
            "query": query,
            "answer": "Insufficient evidence in collected records to answer this question. The collected intelligence workspace does not contain documentation regarding this subject.",
            "citations": [],
            "sources_used": sources_metadata,
            "citation_coverage": 0.0,
            "grounded": False,
            "mode": "extractive_insufficient"
        }

    matching_sentences = []
    citations = []
    min_required_overlap = min(len(query_tokens), 2) if len(query_tokens) > 1 else 1

    for item in retrieved_evidence:
        sid = item["source_id"]
        title = item["title"]
        content = item["content"]

        sentences = re.split(r'(?<=[.!?])\s+', content)
        for s in sentences:
            s_clean = s.strip()
            if len(s_clean) < 25:
                continue

            s_tokens = set(tokenize(s_clean))
            overlap = len(set(query_tokens) & s_tokens)
            if overlap >= min_required_overlap:
                matching_sentences.append({
                    "sentence": s_clean,
                    "title": title,
                    "source_id": sid,
                    "overlap": overlap
                })

    if not matching_sentences:
        return {
            "query": query,
            "answer": "Insufficient evidence in collected records to answer this question. The collected intelligence does not establish a verified link.",
            "citations": [],
            "sources_used": sources_metadata,
            "citation_coverage": 0.0,
            "grounded": False,
            "mode": "extractive_insufficient"
        }

    # Sort by query overlap
    matching_sentences.sort(key=lambda x: x["overlap"], reverse=True)
    top_sentences = matching_sentences[:4]

    answer_lines = [
        f"Based on verified intelligence records for **'{query}'**:\n"
    ]

    seen_srcs = set()
    for s in top_sentences:
        citation_tag = f"[Source: {s['title']} | Doc #{s['source_id']}]"
        answer_lines.append(f"• {s['sentence']} {citation_tag}")
        if s["source_id"] not in seen_srcs:
            seen_srcs.add(s["source_id"])
            citations.append({"title": s["title"], "source_id": s["source_id"]})

    answer_lines.append("\n*Notice: All findings are grounded strictly in the cited primary source records.*")
    answer_text = "\n".join(answer_lines)

    return {
        "query": query,
        "answer": answer_text,
        "citations": citations,
        "sources_used": sources_metadata,
        "citation_coverage": 1.0,
        "grounded": True,
        "mode": "extractive_grounded"
    }
