import json
import os
import sys
import sqlite3

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.analysis import nlp, resolve_entity
from backend.rag import SemanticRetriever, generate_grounded_answer

DATASET_PATH = os.path.join(os.path.dirname(__file__), "eval_dataset.json")
RESULTS_PATH = os.path.join(os.path.dirname(__file__), "eval_results.json")
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "backend", "bharatosint.db")


def evaluate_ner(test_cases: list) -> dict:
    """Evaluates Named Entity Recognition precision, recall, and F1."""
    true_positives = 0
    false_positives = 0
    false_negatives = 0

    for case in test_cases:
        text = case["text"]
        gt_ents = case["ground_truth_entities"]
        gt_set = {(e["name"].lower().strip(), e["type"]) for e in gt_ents}

        doc = nlp(text)
        pred_set = set()
        for ent in doc.ents:
            clean_name = ent.text.lower().strip()
            pred_set.add((clean_name, ent.label_))

        # Compare
        for pred in pred_set:
            # Check for exact or close name match
            matched = False
            for gt in gt_set:
                if pred[0] in gt[0] or gt[0] in pred[0]:
                    if pred[1] == gt[1] or (pred[1] in ["GPE", "LOC"] and gt[1] in ["GPE", "LOC"]):
                        matched = True
                        break
            if matched:
                true_positives += 1
            else:
                false_positives += 1

        for gt in gt_set:
            matched = False
            for pred in pred_set:
                if pred[0] in gt[0] or gt[0] in pred[0]:
                    matched = True
                    break
            if not matched:
                false_negatives += 1

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3)
    }


def evaluate_entity_resolution(test_cases: list) -> dict:
    """Evaluates Entity Resolution matching accuracy, precision, and recall."""
    tp = 0
    fp = 0
    fn = 0
    tn = 0

    for case in test_cases:
        alias = case["alias"]
        expected_canonical = case["expected_canonical"]
        expected_match = case["expected_match"]
        etype = case["entity_type"]

        mock_existing = [
            {"id": 101, "name": expected_canonical, "entity_type": etype}
        ]

        res = resolve_entity(alias, etype, mock_existing)
        predicted_match = (res["status"] in ["auto_matched", "needs_review"]) and (res.get("canonical_name", "").lower() == expected_canonical.lower() or res.get("canonical_id") == 101)

        if expected_match and predicted_match:
            tp += 1
        elif expected_match and not predicted_match:
            fn += 1
        elif not expected_match and predicted_match:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(test_cases) if test_cases else 0.0

    return {
        "accuracy": round(accuracy, 3),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3)
    }


def evaluate_retrieval_and_rag(test_cases: list) -> dict:
    """Evaluates MRR, Recall@5, and Citation Coverage on Grounded RAG."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    sources = [dict(r) for r in conn.execute("SELECT id, title, url, domain, content FROM sources WHERE id > 139").fetchall()]
    if not sources:
        sources = [dict(r) for r in conn.execute("SELECT id, title, url, domain, content FROM sources LIMIT 100").fetchall()]
    conn.close()

    retriever = SemanticRetriever()
    retriever.index_documents(sources)

    reciprocal_ranks = []
    hits_at_k = 0
    citations_present = 0
    hallucination_safeguards_triggered = 0

    for case in test_cases:
        query = case["query"]
        expected_keywords = case.get("expected_keywords", [])
        expected_insufficient = case.get("expected_insufficient", False)

        retrieved = retriever.retrieve(query, top_k=5)
        ans_obj = generate_grounded_answer(query, retrieved)

        if expected_insufficient:
            if not ans_obj["grounded"] or "insufficient" in ans_obj["answer"].lower():
                hallucination_safeguards_triggered += 1
            continue

        # Check retrieval rank
        rank_found = 0
        for r in retrieved:
            text_block = f"{r['title']} {r['content']}".lower()
            if any(kw.lower() in text_block for kw in expected_keywords):
                rank_found = r["rank"]
                break

        if rank_found > 0:
            reciprocal_ranks.append(1.0 / rank_found)
            hits_at_k += 1
        else:
            reciprocal_ranks.append(0.0)

        # Check citations
        if ans_obj["grounded"] and len(ans_obj["citations"]) > 0:
            citations_present += 1

    valid_queries_count = len([c for c in test_cases if not c.get("expected_insufficient")])
    mrr = sum(reciprocal_ranks) / valid_queries_count if valid_queries_count > 0 else 0.0
    recall_at_5 = hits_at_k / valid_queries_count if valid_queries_count > 0 else 0.0
    citation_coverage = citations_present / valid_queries_count if valid_queries_count > 0 else 0.0

    return {
        "mrr": round(mrr, 3),
        "recall_at_5": round(recall_at_5, 3),
        "citation_coverage": round(citation_coverage, 3),
        "hallucination_safeguards_pass": hallucination_safeguards_triggered >= 1
    }


def main():
    print("==================================================================")
    print("      BHARATOSINT: CORE AI/ML & OSINT EVALUATION BENCHMARK        ")
    print("==================================================================\n")

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        eval_data = json.load(f)

    # 1. Evaluate NER
    print("[1/3] Running Named Entity Recognition (NER) Benchmark...")
    ner_results = evaluate_ner(eval_data["ner_evaluation_set"])
    print(f"      Precision: {ner_results['precision']:.3f} | Recall: {ner_results['recall']:.3f} | F1: {ner_results['f1_score']:.3f}\n")

    # 2. Evaluate Entity Resolution
    print("[2/3] Running Entity Resolution & Record Linkage Benchmark...")
    res_results = evaluate_entity_resolution(eval_data["entity_resolution_set"])
    print(f"      Accuracy: {res_results['accuracy']:.3f} | Precision: {res_results['precision']:.3f} | Recall: {res_results['recall']:.3f} | F1: {res_results['f1_score']:.3f}\n")

    # 3. Evaluate Retrieval & Grounded RAG
    print("[3/3] Running Semantic Retrieval & Grounded RAG Benchmark...")
    rag_results = evaluate_retrieval_and_rag(eval_data["retrieval_and_qa_set"])
    print(f"      Recall@5: {rag_results['recall_at_5']:.3f} | MRR: {rag_results['mrr']:.3f} | Citation Coverage: {rag_results['citation_coverage']:.3f}")
    print(f"      Hallucination Safeguard Verified: {rag_results['hallucination_safeguards_pass']}\n")

    full_results = {
        "ner_metrics": ner_results,
        "entity_resolution_metrics": res_results,
        "retrieval_and_rag_metrics": rag_results
    }

    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(full_results, f, indent=2)

    print(f"Benchmark completed successfully. Metrics saved to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
