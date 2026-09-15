import re
import difflib
import spacy

# Load spaCy pipeline
try:
    nlp = spacy.load("en_core_web_sm")
except Exception:
    import en_core_web_sm
    nlp = en_core_web_sm.load()

# Configure custom EntityRuler for Indian agencies and cyber threat indicators
ruler = nlp.add_pipe("entity_ruler", before="ner")
agency_patterns = [
    # Agencies & Ministries
    {"label": "ORG", "pattern": "CERT-In"},
    {"label": "ORG", "pattern": "MeitY"},
    {"label": "ORG", "pattern": "CBI"},
    {"label": "ORG", "pattern": "ED"},
    {"label": "ORG", "pattern": "I4C"},
    {"label": "ORG", "pattern": "NIA"},
    {"label": "ORG", "pattern": "NCIIPC"},
    {"label": "ORG", "pattern": "NSCS"},
    {"label": "ORG", "pattern": "NPCIL"},
    {"label": "ORG", "pattern": "PowerGrid"},
    {"label": "ORG", "pattern": "Delhi Police"},
    {"label": "ORG", "pattern": "Delhi Police Special Cell"},
    {"label": "ORG", "pattern": "Mumbai Police"},
    {"label": "ORG", "pattern": "Maharashtra Cyber"},
    {"label": "ORG", "pattern": "Cyberabad Police"},
    {"label": "ORG", "pattern": "Pune Police"},
    {"label": "ORG", "pattern": "IFSO"},
    {"label": "ORG", "pattern": "Cosmos Bank"},
    {"label": "ORG", "pattern": "AIIMS"},
    {"label": "ORG", "pattern": "AIIMS Delhi"},
    {"label": "ORG", "pattern": "SLDC"},
    {"label": "ORG", "pattern": "NTPC"},
    {"label": "ORG", "pattern": "DoT"},
    {"label": "ORG", "pattern": "NIC"},
    # Operations
    {"label": "EVENT", "pattern": "Operation Chakra-I"},
    {"label": "EVENT", "pattern": "Operation Chakra-II"},
    {"label": "EVENT", "pattern": "Operation Chakra"},
    {"label": "EVENT", "pattern": "Operation Meghdoot"},
    # Threat Groups & Tools
    {"label": "THREAT", "pattern": "ShadowPad"},
    {"label": "THREAT", "pattern": "RedEcho"},
    {"label": "THREAT", "pattern": "Dtrack"},
    {"label": "THREAT", "pattern": "Lazarus"},
    {"label": "THREAT", "pattern": "LockBit 3.0"},
    {"label": "THREAT", "pattern": "LockBit"},
    {"label": "THREAT", "pattern": "Cobalt Strike"},
    {"label": "THREAT", "pattern": "Akira"},
    {"label": "THREAT", "pattern": "Pegasus"},
]
ruler.add_patterns(agency_patterns)

# -------------------------------------------------------------
# INDIA-SPECIFIC INTELLIGENCE: ALIASES & ACRONYMS
# -------------------------------------------------------------
INDIAN_AGENCY_ALIASES = {
    "cbi": ("Central Bureau of Investigation", "organization"),
    "central bureau of investigation": ("Central Bureau of Investigation", "organization"),
    "ed": ("Enforcement Directorate", "organization"),
    "enforcement directorate": ("Enforcement Directorate", "organization"),
    "directorate of enforcement": ("Enforcement Directorate", "organization"),
    "cert-in": ("Indian Computer Emergency Response Team", "organization"),
    "cert in": ("Indian Computer Emergency Response Team", "organization"),
    "indian computer emergency response team": ("Indian Computer Emergency Response Team", "organization"),
    "i4c": ("Indian Cyber Crime Coordination Centre", "organization"),
    "indian cyber crime coordination centre": ("Indian Cyber Crime Coordination Centre", "organization"),
    "nia": ("National Investigation Agency", "organization"),
    "national investigation agency": ("National Investigation Agency", "organization"),
    "nciipc": ("National Critical Information Infrastructure Protection Centre", "organization"),
    "national critical information infrastructure protection centre": ("National Critical Information Infrastructure Protection Centre", "organization"),
    "meity": ("Ministry of Electronics and Information Technology", "organization"),
    "ministry of electronics and information technology": ("Ministry of Electronics and Information Technology", "organization"),
    "mha": ("Ministry of Home Affairs", "organization"),
    "ministry of home affairs": ("Ministry of Home Affairs", "organization"),
    "rbi": ("Reserve Bank of India", "organization"),
    "reserve bank of india": ("Reserve Bank of India", "organization"),
    "npcil": ("Nuclear Power Corporation of India Limited", "organization"),
    "nuclear power corporation of india limited": ("Nuclear Power Corporation of India Limited", "organization"),
    "kknpp": ("Kudankulam Nuclear Power Plant", "location"),
    "kudankulam nuclear power plant": ("Kudankulam Nuclear Power Plant", "location"),
    "aiims": ("All India Institute of Medical Sciences", "organization"),
    "aiims delhi": ("All India Institute of Medical Sciences", "organization"),
    "all india institute of medical sciences": ("All India Institute of Medical Sciences", "organization"),
    "delhi police special cell": ("Delhi Police Special Cell", "organization"),
    "ifso": ("Intelligence Fusion and Strategic Operations", "organization"),
    "cosmos bank": ("Cosmos Co-operative Bank", "organization"),
    "cosmos co-operative bank": ("Cosmos Co-operative Bank", "organization"),
}

INDIAN_HONORIFICS = [
    r"^dr\.\s*",
    r"^lt\.\s*gen\.\s*",
    r"^gen\.\s*",
    r"^cds\s*",
    r"^shri\s*",
    r"^smt\.\s*",
    r"^union\s*minister\s*",
    r"^minister\s*",
    r"^director\s*general\s*",
    r"^director\s*",
    r"^deputy\s*commissioner\s*of\s*police\s*",
    r"^special\s*commissioner\s*of\s*police\s*",
    r"^additional\s*director\s*general\s*of\s*police\s*",
    r"^deputy\s*governor\s*",
    r"^dcp\s*",
    r"^adg\s*",
    r"^commissioner\s*",
]

THREAT_KEYWORDS = [
    "cyber attack", "cyberattack", "ransomware", "malware", "phishing",
    "smishing", "data breach", "hacking", "vulnerability", "exploit",
    "terror", "terrorist", "espionage", "surveillance", "fraud",
    "digital arrest", "mule account", "sim box", "scam", "ddos",
    "botnet", "trojan", "spyware", "infostealer", "crypto laundering"
]


# -------------------------------------------------------------
# INDIAN TRANSLITERATION & SPELLING NORMALIZER
# -------------------------------------------------------------

def normalize_indian_name(name: str) -> str:
    """Normalizes honorifics and common Indian phonetics/transliterations."""
    clean = name.strip()
    clean_lower = clean.lower()

    # Strip honorifics
    for h in INDIAN_HONORIFICS:
        clean = re.sub(h, "", clean, flags=re.IGNORECASE).strip()

    norm = clean.lower()
    # Normalize initials e.g. "M.U. Nair" -> "m u nair"
    norm = re.sub(r'\.([A-Za-z])', r' \1', norm)
    norm = norm.replace('.', ' ').strip()

    # Common Indian transliteration substitutions
    norm = re.sub(r'\bmohd\b', 'mohammad', norm)
    norm = re.sub(r'\bmohammed\b', 'mohammad', norm)
    norm = re.sub(r'laxmi', 'lakshmi', norm)
    norm = re.sub(r'chowdhary', 'chaudhary', norm)
    norm = re.sub(r'chowdhury', 'chaudhary', norm)
    norm = re.sub(r'shrivastava', 'srivastava', norm)
    norm = re.sub(r'suneel', 'sunil', norm)
    norm = re.sub(r'deepak', 'dipak', norm)
    norm = re.sub(r'asok', 'ashok', norm)

    # Collapse repeated whitespace
    norm = " ".join(norm.split())
    return norm, clean


def calculate_similarity(s1: str, s2: str) -> float:
    """Computes combined token overlap and sequence matcher ratio."""
    ratio = difflib.SequenceMatcher(None, s1, s2).ratio()
    tokens1 = set(s1.split())
    tokens2 = set(s2.split())
    if not tokens1 or not tokens2:
        return ratio
    token_jaccard = len(tokens1 & tokens2) / len(tokens1 | tokens2)
    return round((ratio * 0.6) + (token_jaccard * 0.4), 3)


# -------------------------------------------------------------
# ENTITY RESOLUTION ENGINE
# -------------------------------------------------------------

def resolve_entity(name: str, entity_type: str, existing_canonical_entities: list) -> dict:
    """
    Resolves an incoming entity name against existing canonical entities.
    Returns:
      {
        'canonical_id': int or None,
        'canonical_name': str,
        'match_score': float,
        'rationale': str,
        'status': 'auto_matched' | 'needs_review' | 'new_entity'
      }
    """
    raw_lower = name.lower().strip()
    norm_name, clean_name = normalize_indian_name(name)

    # 1. Known Indian Agency / Abbreviation Match
    if raw_lower in INDIAN_AGENCY_ALIASES:
        canon_name, canon_type = INDIAN_AGENCY_ALIASES[raw_lower]
        # Match against existing entities
        for cand in existing_canonical_entities:
            if cand["name"].lower() == canon_name.lower():
                return {
                    "canonical_id": cand["id"],
                    "canonical_name": cand["name"],
                    "match_score": 0.98,
                    "rationale": f"Matched via official Indian agency acronym/alias rule ('{name}' -> '{canon_name}')",
                    "status": "auto_matched"
                }
        # If canonical doesn't exist yet, return canonical name as primary
        return {
            "canonical_id": None,
            "canonical_name": canon_name,
            "match_score": 0.98,
            "rationale": f"Canonicalized via official Indian agency acronym rule ('{name}' -> '{canon_name}')",
            "status": "auto_matched"
        }

    # 2. Check against existing canonical entities in the investigation
    best_match = None
    highest_score = 0.0
    rationale = "New unique entity"

    for cand in existing_canonical_entities:
        cand_name = cand["name"]
        cand_type = cand.get("entity_type") or cand.get("type")

        # Skip cross-type matching unless one is generic
        if cand_type and cand_type != entity_type:
            continue

        cand_norm, cand_clean = normalize_indian_name(cand_name)

        # Exact match after normalization
        if norm_name == cand_norm:
            return {
                "canonical_id": cand["id"],
                "canonical_name": cand_name,
                "match_score": 1.0,
                "rationale": f"Exact match after honorific & transliteration normalization ('{name}' == '{cand_name}')",
                "status": "auto_matched"
            }

        # Substring / Title variation (e.g. 'Praveen Sood' vs 'Director Praveen Sood')
        if (cand_clean.lower() in clean_name.lower()) or (clean_name.lower() in cand_clean.lower()):
            if len(clean_name) >= 4 and len(cand_clean) >= 4:
                score = 0.90
                if score > highest_score:
                    highest_score = score
                    best_match = cand
                    rationale = f"Title/honorific stripped entity overlap ('{name}' <-> '{cand_name}')"

        # String & Phonetic Similarity
        sim = calculate_similarity(norm_name, cand_norm)
        if sim > highest_score:
            highest_score = sim
            best_match = cand
            rationale = f"String & token overlap similarity ({sim:.2f}) with '{cand_name}'"

    # Evaluation of threshold
    if best_match:
        if highest_score >= 0.85:
            return {
                "canonical_id": best_match["id"],
                "canonical_name": best_match["name"],
                "match_score": highest_score,
                "rationale": rationale,
                "status": "auto_matched"
            }
        elif highest_score >= 0.65:
            return {
                "canonical_id": best_match["id"],
                "canonical_name": best_match["name"],
                "match_score": highest_score,
                "rationale": rationale + " - flagged for human analyst review",
                "status": "needs_review"
            }

    return {
        "canonical_id": None,
        "canonical_name": clean_name if len(clean_name) > 2 else name,
        "match_score": 0.0,
        "rationale": "No previous matching entity found; created as new canonical entity.",
        "status": "new_entity"
    }


# -------------------------------------------------------------
# RELATIONSHIP EXTRACTION (TYPED WITH CONFIDENCE & EVIDENCE)
# -------------------------------------------------------------

def extract_typed_relationships(doc_spacy, text: str, source_id: int = None) -> list:
    """
    Extracts typed relationships:
      - works_for / leads: PERSON -> ORG
      - located_at: ORG/EVENT/PERSON -> GPE/LOC
      - associated_with: ORG/THREAT -> ORG/THREAT
      - mentions: Co-occurring within sentence
    Attaches exact evidence sentence and confidence score.
    """
    relationships = []
    seen = set()

    for sent in doc_spacy.sents:
        sent_text = sent.text.strip()
        ents = [e for e in sent.ents if len(e.text.strip()) > 1]

        if len(ents) < 2:
            continue

        for i in range(len(ents)):
            for j in range(len(ents)):
                if i == j:
                    continue

                e1, e2 = ents[i], ents[j]
                t1, t2 = e1.label_, e2.label_
                n1, n2 = e1.text.strip(), e2.text.strip()

                if n1.lower() == n2.lower():
                    continue

                rel_type = None
                confidence = 0.70

                sent_lower = sent_text.lower()

                # Rule 1: PERSON -> works_for / leads -> ORG
                if t1 == "PERSON" and t2 == "ORG":
                    if any(w in sent_lower for w in ["director", "chief", "officer", "commissioner", "minister", "head", "leads", "at", "of"]):
                        rel_type = "works_for"
                        confidence = 0.92
                    else:
                        rel_type = "associated_with"
                        confidence = 0.75

                # Rule 2: ORG / PERSON / EVENT -> located_at -> GPE / LOC
                elif t2 in ["GPE", "LOC"] and t1 in ["ORG", "PERSON", "EVENT"]:
                    if any(w in sent_lower for w in ["in", "at", "located", "based", "across"]):
                        rel_type = "located_at"
                        confidence = 0.88
                    else:
                        rel_type = "mentions"
                        confidence = 0.70

                # Rule 3: THREAT -> associated_with -> ORG or THREAT
                elif t1 == "THREAT" or t2 == "THREAT":
                    if any(w in sent_lower for w in ["targeted", "targeting", "compromised", "deployed", "ransomware", "trojan", "malware", "scam"]):
                        rel_type = "associated_with"
                        confidence = 0.85
                    else:
                        rel_type = "mentions"
                        confidence = 0.65

                # Rule 4: ORG -> associated_with -> ORG
                elif t1 == "ORG" and t2 == "ORG":
                    if any(w in sent_lower for w in ["collaborated", "joint", "coordinated", "with", "investigated", "alongside"]):
                        rel_type = "associated_with"
                        confidence = 0.82
                    else:
                        rel_type = "mentions"
                        confidence = 0.60

                if rel_type:
                    key = (n1.lower(), rel_type, n2.lower())
                    if key not in seen:
                        seen.add(key)
                        relationships.append({
                            "source": n1,
                            "source_type": t1.lower(),
                            "relationship": rel_type,
                            "target": n2,
                            "target_type": t2.lower(),
                            "evidence": sent_text[:500],
                            "confidence": confidence,
                            "source_id": source_id
                        })

    return relationships


# -------------------------------------------------------------
# MAIN ANALYSIS PIPELINE
# -------------------------------------------------------------

def analyze_articles(articles: list, existing_entities: list = None) -> dict:
    """
    Analyzes a collection of article objects:
    - Runs spaCy NLP with Indian custom rules
    - Resolves entities against existing database entities
    - Extracts typed relationships with evidence and confidence
    - Returns structured analytical summary
    """
    if existing_entities is None:
        existing_entities = []

    people = {}
    organizations = {}
    locations = {}
    dates = set()
    events = set()
    threat_indicators = set()
    emails = set()
    urls = set()
    all_relationships = []

    full_text_list = []

    for art in articles:
        content = art.get("article", {}).get("content", "") or art.get("content", "")
        if not content:
            continue

        full_text_list.append(content)
        source_id = art.get("source_id") or art.get("id")

        # Run spaCy
        doc = nlp(content)

        # Extract entities
        for ent in doc.ents:
            text_val = ent.text.strip()
            if len(text_val) <= 2 or text_val.isdigit():
                continue

            lbl = ent.label_

            if lbl == "PERSON":
                res = resolve_entity(text_val, "person", existing_entities)
                people[res["canonical_name"]] = res
            elif lbl == "ORG":
                res = resolve_entity(text_val, "organization", existing_entities)
                organizations[res["canonical_name"]] = res
            elif lbl in ["GPE", "LOC"]:
                res = resolve_entity(text_val, "location", existing_entities)
                locations[res["canonical_name"]] = res
            elif lbl == "DATE":
                dates.add(text_val)
            elif lbl == "EVENT":
                events.add(text_val)
            elif lbl == "THREAT":
                threat_indicators.add(text_val)

        # Extract relationships with sentence evidence
        rels = extract_typed_relationships(doc, content, source_id)
        all_relationships.extend(rels)

        # Extract emails & URLs
        emails.update(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', content))
        urls.update(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content))

        # Check threat keywords
        content_lower = content.lower()
        for kw in THREAT_KEYWORDS:
            if kw in content_lower:
                threat_indicators.add(kw)

    # Risk level calculation
    threat_count = len(threat_indicators)
    if threat_count >= 8:
        risk_level = "HIGH"
    elif threat_count >= 4:
        risk_level = "MEDIUM"
    elif threat_count >= 1:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    # Deduplicate relationships
    unique_rels = []
    seen_rel = set()
    for r in all_relationships:
        key = (r["source"].lower(), r["relationship"], r["target"].lower())
        if key not in seen_rel:
            seen_rel.add(key)
            unique_rels.append(r)

    summary = (
        f"NLP Analysis completed across {len(articles)} source documents. "
        f"Identified {len(people)} people, {len(organizations)} organizations, "
        f"{len(locations)} locations, {len(events)} events, and {len(unique_rels)} evidence-backed relationships. "
        f"Threat assessment: {risk_level} ({threat_count} threat indicators detected)."
    )

    return {
        "articles_analyzed": len(articles),
        "risk_level": risk_level,
        "summary": summary,
        "entities": {
            "people": people,
            "organizations": organizations,
            "locations": locations,
            "dates": sorted(list(dates)),
            "events": sorted(list(events))
        },
        "threat_indicators": sorted(list(threat_indicators)),
        "emails": sorted(list(emails)),
        "urls": sorted(list(urls))[:25],
        "relationships": unique_rels
    }