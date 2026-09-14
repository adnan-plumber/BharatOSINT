import re


THREAT_KEYWORDS = [
    "cyber attack",
    "cyberattack",
    "ransomware",
    "malware",
    "phishing",
    "data breach",
    "hacking",
    "vulnerability",
    "exploit",
    "terror",
    "terrorist",
    "espionage",
    "surveillance",
    "fraud",
    "scam",
    "ddos",
    "botnet",
    "trojan",
    "spyware"
]


def analyze_articles(articles):

    all_text = " ".join(
        article.get("article", {}).get("content", "")
        for article in articles
    )

    text_lower = all_text.lower()

    # =====================================
    # BASIC ENTITY EXTRACTION
    # =====================================

    people = set()
    organizations = set()
    locations = set()
    dates = set()

        # =====================================
    # LIGHTWEIGHT ENTITY EXTRACTION
    # =====================================

    # Dates
    date_patterns = re.findall(
        r'\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}'
        r'|\d{4}[/-]\d{1,2}[/-]\d{1,2}'
        r'|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|'
        r'Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|'
        r'Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+'
        r'\d{1,2},?\s+\d{4})\b',
        all_text,
        re.IGNORECASE
    )

    dates.update(date_patterns)

    # Capitalized names
    name_patterns = re.findall(
        r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b',
        all_text
    )

    # Organization keywords
    org_keywords = [
        "Ltd", "Limited", "Inc", "Corporation",
        "Corp", "Company", "Group", "Bank",
        "University", "Institute", "Ministry",
        "Government", "Agency", "Police", "Army"
    ]

    for name in name_patterns:

        name = name.strip()

        if any(
            keyword.lower() in name.lower()
            for keyword in org_keywords
        ):
            organizations.add(name)
        else:
            people.add(name)

    # Locations
    location_keywords = [
        "India",
        "Delhi",
        "Mumbai",
        "Indore",
        "Bhopal",
        "Bengaluru",
        "Bangalore",
        "Hyderabad",
        "Chennai",
        "Kolkata",
        "Pune",
        "Jaipur",
        "Madhya Pradesh",
        "Maharashtra",
        "Gujarat",
        "Rajasthan",
        "Uttar Pradesh",
        "United States",
        "United Kingdom",
        "Russia",
        "China",
        "Pakistan",
        "Iran",
        "Israel"
    ]

    for location in location_keywords:

        if re.search(
            r'\b' + re.escape(location) + r'\b',
            all_text,
            re.IGNORECASE
        ):
            locations.add(location)

    # Email extraction
    emails = list(set(re.findall(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        all_text
    )))

    # URL extraction
    urls = list(set(re.findall(
        r'https?://[^\s]+',
        all_text
    )))

    # =====================================
    # THREAT DETECTION
    # =====================================

    found_threats = []

    for keyword in THREAT_KEYWORDS:
        if keyword in text_lower:
            found_threats.append(keyword)

    # =====================================
    # RISK CALCULATION
    # =====================================

    threat_count = len(found_threats)

    if threat_count >= 8:
        risk_level = "HIGH"
    elif threat_count >= 4:
        risk_level = "MEDIUM"
    elif threat_count >= 1:
        risk_level = "LOW"
    else:
        risk_level = "UNKNOWN"

    # =====================================
    # RELATIONSHIP EXTRACTION
    # =====================================

    relationships = []

    # Threat ↔ Threat
    for article in articles:

        content = article.get("article", {}).get("content", "")

        if not content:
            continue

        article_text = content.lower()

        article_threats = []

        for threat in THREAT_KEYWORDS:
            if threat in article_text:
                article_threats.append(threat)

        for i in range(len(article_threats)):
            for j in range(i + 1, len(article_threats)):

                relationships.append({
                    "source": article_threats[i],
                    "relationship": "co_occurs_with",
                    "target": article_threats[j]
                })

    # =====================================
    # SUMMARY
    # =====================================

    summary = (
        f"Analysis completed across {len(articles)} articles. "
        f"Detected {len(people)} people, "
        f"{len(organizations)} organizations, "
        f"{len(locations)} locations and "
        f"{threat_count} threat indicators."
    )

    # =====================================
    # REMOVE DUPLICATES
    # =====================================

    unique_relationships = []

    seen = set()

    for relation in relationships:

        key = (
            relation["source"],
            relation["relationship"],
            relation["target"]
        )

        if key not in seen:

            seen.add(key)
            unique_relationships.append(relation)

    # =====================================
    # FINAL RESULT
    # =====================================

    return {

        "articles_analyzed": len(articles),

        "risk_level": risk_level,

        "summary": summary,

        "entities": {

            "people": sorted(people),

            "organizations": sorted(organizations),

            "locations": sorted(locations),

            "dates": sorted(dates),

            "relationships": unique_relationships
        },

        "threat_indicators": found_threats,

        "emails": emails,

        "relationships": unique_relationships,

        "urls": urls
    }