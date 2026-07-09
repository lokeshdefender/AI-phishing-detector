from typing import List, Dict
from .utils import (
    extract_urls,
    is_ip_url,
    is_shortener,
    domain_from_url,
    extract_sender,
    is_free_email_address,
    get_domain_age_days,
    get_dns_records,
    is_suspicious_tld,
    is_newly_registered,
)
from .report_generator import generate_analyst_report

# High-confidence phishing keywords (always suspicious)
HIGH_CONFIDENCE_PHISHING_KEYWORDS = [
    "verify account",
    "confirm identity",
    "confirm your account",
    "validate account",
    "verify password",
    "reset password",
    "click here",
    "confirm email",
    "verify email",
    "confirm now",
    "act immediately",
    "suspend account",
    "limited access",
    "unusual activity",
    "unauthorized access",
    "final notice",
    "urgent action",
    "immediate action",
]

# Context-dependent keywords (only suspicious in phishing contexts)
CONTEXT_DEPENDENT_KEYWORDS = {
    "update": ["account", "password", "credentials", "information"],
    "confirm": ["identity", "account", "email", "password"],
    "click": ["here", "link", "verify", "confirm"],
    "urgent": ["action", "verify", "confirm", "update"],
    "account": ["verify", "confirm", "suspended", "unauthorized"],
    "security": ["verify", "confirm", "urgent", "alert"],
}

# Common legitimate business words that should NOT be flagged
LEGITIMATE_BUSINESS_KEYWORDS = [
    "updates",
    "meeting",
    "agenda",
    "team",
    "project",
    "feedback",
    "reminder",
    "schedule",
    "report",
]

BRAND_KEYWORDS = ["paypal", "apple", "google", "amazon", "microsoft", "bankofamerica", "chase"]


def _is_phishing_context(text_lower: str, keyword: str) -> bool:
    """Check if a context-dependent keyword appears in a phishing context."""
    if keyword not in CONTEXT_DEPENDENT_KEYWORDS:
        return False
    
    phishing_indicators = CONTEXT_DEPENDENT_KEYWORDS[keyword]
    
    # Check if any phishing indicator appears near the keyword
    for indicator in phishing_indicators:
        # Look for patterns within 50 characters
        for i, _ in enumerate(text_lower):
            if text_lower[i:].startswith(keyword):
                snippet = text_lower[max(0, i-30):min(len(text_lower), i+len(keyword)+30)]
                if indicator in snippet:
                    return True
                break
    
    return False


def _detect_suspicious_keywords(text_lower: str) -> List[str]:
    """Detect suspicious keywords, considering context."""
    found_kw = []
    
    # Check high-confidence phishing keywords
    for keyword in HIGH_CONFIDENCE_PHISHING_KEYWORDS:
        if keyword in text_lower:
            found_kw.append(keyword)
    
    # Check context-dependent keywords
    for keyword in CONTEXT_DEPENDENT_KEYWORDS.keys():
        if keyword in text_lower:
            # Skip if it's a legitimate business word in non-phishing context
            if keyword in ["update", "updates", "meeting", "agenda", "team", "project", 
                          "feedback", "reminder", "schedule", "report"]:
                # Check if it's used legitimately (e.g., "project updates", "team meeting")
                before_context = " ".join(text_lower.split())
                
                # Skip legitimate patterns
                if f"{keyword}s" in text_lower and keyword == "update":
                    continue  # Skip "updates"
                if keyword == "meeting" and any(w in text_lower for w in ["team meeting", "calendar meeting", "scheduled meeting"]):
                    continue
                if keyword == "agenda" and any(w in text_lower for w in ["meeting agenda", "team agenda"]):
                    continue
                if keyword == "team" and any(w in text_lower for w in ["team meeting", "team project", "team members", "team feedback"]):
                    continue
                if keyword == "project" and any(w in text_lower for w in ["project updates", "project team", "project deadline", "project status"]):
                    continue
                if keyword == "feedback" and any(w in text_lower for w in ["team feedback", "project feedback", "your feedback"]):
                    continue
                if keyword == "reminder" and any(w in text_lower for w in ["calendar reminder", "meeting reminder", "task reminder"]):
                    continue
                if keyword == "schedule" and any(w in text_lower for w in ["meeting schedule", "calendar schedule"]):
                    continue
                if keyword == "report" and any(w in text_lower for w in ["monthly report", "status report", "team report"]):
                    continue
            
            # For other keywords, check phishing context
            if _is_phishing_context(text_lower, keyword):
                found_kw.append(keyword)
    
    return found_kw


def analyze_email(email_text: str) -> Dict:
    urls = extract_urls(email_text)
    indicators = []
    score = 0

    text_lower = email_text.lower()

    # Sender analysis
    sender = extract_sender(email_text)
    if sender:
        sender_domain = sender.split('@')[-1].lower() if '@' in sender else ''
        if is_free_email_address(sender):
            indicators.append({
                "indicator": "free_sender",
                "reason": f"Sender appears to use a free email address ({sender})",
                "weight": 8,
            })
            score += 8

    # Indicator: IP address in URL (high risk)
    if any(is_ip_url(u) for u in urls):
        indicators.append({"indicator": "ip_in_url", "reason": "URL uses an IP address instead of a domain", "weight": 30})
        score += 30

    # Indicator: URL shorteners
    if any(is_shortener(u) for u in urls):
        indicators.append({"indicator": "url_shortener", "reason": "URL uses a known shortening service", "weight": 18})
        score += 18

    # Indicator: multiple links
    if len(urls) >= 3:
        indicators.append({"indicator": "multiple_links", "reason": "Multiple links in the email (>=3)", "weight": 8})
        score += 8

    # Suspicious keywords and urgency language
    found_kw = _detect_suspicious_keywords(text_lower)
    if found_kw:
        kw_weight = min(len(found_kw) * 6, 30)
        indicators.append({"indicator": "suspicious_keywords", "reason": f"Found suspicious words: {', '.join(found_kw)}", "weight": kw_weight})
        score += kw_weight

    # Urgency score (exclamation marks and urgent phrases)
    urgency_hits = 0
    urgency_hits += text_lower.count('!')
    urgency_phrases = ["immediately", "asap", "act now", "within 24 hours", "final notice", "last chance", "urgent"]
    for p in urgency_phrases:
        if p in text_lower:
            urgency_hits += 1
    if urgency_hits:
        w = min(20, urgency_hits * 6)
        indicators.append({"indicator": "urgency", "reason": f"Urgent language detected ({urgency_hits} hits)", "weight": w})
        score += w

    # Credential harvesting detection
    cred_terms = ["password", "passcode", "credentials", "ssn", "social security", "account number", "routing number", "pin", "cvv"]
    cred_hits = [t for t in cred_terms if t in text_lower]
    if cred_hits:
        # increase weight if multiple sensitive fields requested or a link is present
        if len(cred_hits) >= 2 and (urls or 'login' in text_lower or 'sign in' in text_lower):
            weight = 50
        else:
            weight = 25 if (urls or 'login' in text_lower or 'sign in' in text_lower) else 12
        indicators.append({"indicator": "credential_harvest", "reason": f"Credentials or sensitive info requested: {', '.join(cred_hits)}", "weight": weight})
        score += weight

    # Domain-level signals: brand mismatch, WHOIS age, DNS records, suspicious TLDs
    for u in urls:
        d = domain_from_url(u)

        # brand mismatch
        for brand in BRAND_KEYWORDS:
            if brand in d and not d.split('.')[0].startswith(brand):
                indicators.append({"indicator": "brand_mismatch", "reason": f"Domain {d} may impersonate {brand}", "weight": 22})
                score += 22

        # WHOIS domain age
        try:
            age_days = get_domain_age_days(d)
            if age_days is None:
                indicators.append({"indicator": "whois_unavailable", "reason": f"WHOIS lookup unavailable for {d}", "weight": 0})
            else:
                if age_days <= 90:
                    indicators.append({"indicator": "new_domain", "reason": f"Domain {d} was registered recently ({age_days} days)", "weight": 30})
                    score += 30
                elif age_days <= 365:
                    indicators.append({"indicator": "young_domain", "reason": f"Domain {d} is young ({age_days} days)", "weight": 10})
                    score += 10
        except Exception:
            indicators.append({"indicator": "whois_error", "reason": f"WHOIS check error for {d}", "weight": 0})

        # DNS checks
        try:
            dns_info = get_dns_records(d)
            if not dns_info.get('A'):
                indicators.append({"indicator": "no_a_record", "reason": f"Domain {d} has no A records", "weight": 20})
                score += 20
            if not dns_info.get('MX'):
                # missing MX could indicate misconfigured or disposable domain
                indicators.append({"indicator": "no_mx_record", "reason": f"Domain {d} has no MX records", "weight": 6})
                score += 6
        except Exception:
            indicators.append({"indicator": "dns_error", "reason": f"DNS check failed for {d}", "weight": 0})

        # Suspicious TLDs
        if is_suspicious_tld(d):
            indicators.append({"indicator": "suspicious_tld", "reason": f"Domain {d} uses a suspicious TLD", "weight": 12})
            score += 12

        # Suspicious endpoints (login/verify) increase risk
        if '/login' in u.lower() or 'verify' in u.lower():
            indicators.append({"indicator": "suspicious_endpoint", "reason": f"URL looks like a login/verification endpoint: {u}", "weight": 8})
            score += 8

    # Suspicious sender vs content: if body mentions a brand but sender domain doesn't match
    if sender and any(b in text_lower for b in BRAND_KEYWORDS):
        sd = sender.split('@')[-1].lower() if '@' in sender else ''
        if not any(b in sd for b in BRAND_KEYWORDS):
            indicators.append({"indicator": "sender_brand_mismatch", "reason": f"Email mentions brands but sender domain ({sd}) does not match", "weight": 12})
            score += 12

    # Normalize score
    score = max(0, min(100, score))

    # Confidence: higher when strong signals present
    strong_count = sum(1 for i in indicators if i['weight'] >= 20)
    confidence = min(100, int(score + strong_count * 8))

    explanation = generate_explanation(indicators)
    
    # Generate SOC analyst-style report
    analyst_report = generate_analyst_report(
        score=score,
        indicators=indicators,
        urls=urls,
        sender=sender,
        email_text=email_text
    )

    return {
        "urls": urls,
        "score": int(score),
        "confidence": int(confidence),
        "indicators": indicators,
        "explanation": explanation,
        "sender": sender,
        "analyst_report": analyst_report,
    }


def generate_explanation(indicators: List[Dict]) -> str:
    if not indicators:
        return "No obvious phishing indicators detected. Score is low but remain cautious. Avoid clicking links from unknown senders."
    parts = []
    for i in indicators:
        advice = _advice_for_indicator(i['indicator'])
        parts.append(f"- {i['reason']} (weight={i['weight']})\n  Recommendation: {advice}")
    parts.append("General: Do not click suspicious links, verify the sender by other means, and check destination domains by hovering or typing URLs manually.")
    return "\n\n".join(parts)


def _advice_for_indicator(ind: str) -> str:
    mapping = {
        'ip_in_url': 'Avoid the link; IP addresses are uncommon for legitimate services.',
        'url_shortener': 'Shortened links hide destination; expand or avoid clicking.',
        'multiple_links': 'Multiple unrelated links may indicate malicious campaigns.',
        'suspicious_keywords': 'Words asking for verification or urgency often accompany scams.',
        'urgency': 'Scammers create urgency; pause and verify before acting.',
        'credential_harvest': 'Never submit passwords or SSNs via unsolicited links; go directly to the official site.',
        'brand_mismatch': 'Domain appears to impersonate a brand; do not enter credentials.',
        'free_sender': 'Free email providers are sometimes used for scams; verify sender identity.',
        'sender_brand_mismatch': 'Sender domain does not match mentioned brand; likely spoofed.',
        'whois_unavailable': 'WHOIS data unavailable; inability to verify domain age increases uncertainty.',
        'whois_error': 'WHOIS lookup failed; treat domain with caution.',
        'new_domain': 'Newly registered domains are commonly used in phishing campaigns; avoid entering credentials.',
        'young_domain': 'Relatively new domain; proceed with caution and verify via independent channels.',
        'no_a_record': 'Domain does not resolve to an IP address; link may be broken or malicious.',
        'no_mx_record': 'Domain lacks MX records; could indicate disposable or misconfigured domain.',
        'suspicious_tld': 'The domain uses a TLD often associated with abusive registrations.',
        'suspicious_endpoint': 'Login/verify endpoints in unsolicited emails often lead to credential harvesters.',
        'dns_error': 'DNS check failed; treat domain with extra caution.',
    }
    return mapping.get(ind, 'Exercise caution and verify via independent channels.')
