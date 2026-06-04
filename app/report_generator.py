"""Generate SOC analyst-style phishing reports."""

from typing import List, Dict


def generate_analyst_report(
    score: int,
    indicators: List[Dict],
    urls: List[str],
    sender: str,
    email_text: str,
) -> Dict:
    """Generate a comprehensive SOC analyst-style phishing report."""
    
    # Determine threat level
    threat_level = _get_threat_level(score)
    
    # Generate executive summary
    exec_summary = _generate_executive_summary(threat_level, score, indicators)
    
    # Generate threat assessment
    threat_assessment = _generate_threat_assessment(indicators, sender, score)
    
    # Summarize key indicators
    indicators_summary = _summarize_indicators(indicators)
    
    # Generate remediation recommendations
    remediation = _generate_remediation(threat_level, indicators, urls)
    
    # Generate detection rationale
    detection_rationale = _generate_detection_rationale(indicators, score)
    
    return {
        "threat_level": threat_level,
        "executive_summary": exec_summary,
        "threat_assessment": threat_assessment,
        "key_indicators": indicators_summary,
        "detection_rationale": detection_rationale,
        "remediation_recommendations": remediation,
        "confidence_percentage": min(100, score + len([i for i in indicators if i['weight'] >= 20]) * 5),
    }


def _get_threat_level(score: int) -> str:
    """Map risk score to threat level."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "MINIMAL"


def _generate_executive_summary(threat_level: str, score: int, indicators: List[Dict]) -> str:
    """Generate executive summary for the report."""
    ind_count = len(indicators)
    high_weight_count = len([i for i in indicators if i['weight'] >= 20])
    
    summary = f"""Email classified as {threat_level} threat (Risk Score: {score}/100).
Analysis identified {ind_count} phishing indicators, with {high_weight_count} high-confidence signals.
"""
    
    if threat_level in ["CRITICAL", "HIGH"]:
        summary += "Immediate user awareness and potential incident response recommended."
    elif threat_level == "MEDIUM":
        summary += "Exercise caution; verify sender through alternative channels before clicking links."
    else:
        summary += "Low risk, but standard email security practices should be applied."
    
    return summary.strip()


def _generate_threat_assessment(indicators: List[Dict], sender: str, score: int) -> str:
    """Generate threat assessment narrative."""
    
    cred_harvest = any(i['indicator'] == 'credential_harvest' for i in indicators)
    urgency = any(i['indicator'] == 'urgency' for i in indicators)
    ip_url = any(i['indicator'] == 'ip_in_url' for i in indicators)
    brand_mismatch = any(i['indicator'] == 'brand_mismatch' for i in indicators)
    new_domain = any(i['indicator'] == 'new_domain' for i in indicators)
    
    assessment = "Threat Assessment: "
    
    tactics = []
    if cred_harvest:
        tactics.append("credential harvesting")
    if urgency:
        tactics.append("social engineering through artificial urgency")
    if ip_url:
        tactics.append("obfuscated infrastructure")
    if brand_mismatch:
        tactics.append("brand impersonation")
    if new_domain:
        tactics.append("recently registered malicious domain")
    
    if tactics:
        assessment += f"This email employs tactics consistent with {', '.join(tactics)}. "
    
    assessment += f"The sender ({sender or 'unknown'}) exhibits {len(indicators)} suspicious characteristics. "
    
    if score >= 70:
        assessment += "Attack vector appears highly coordinated and targeted."
    elif score >= 40:
        assessment += "Attack vector shows moderate sophistication."
    else:
        assessment += "Attack vector appears opportunistic."
    
    return assessment.strip()


def _summarize_indicators(indicators: List[Dict]) -> List[Dict]:
    """Summarize key indicators with analyst commentary."""
    
    summary = []
    for ind in indicators:
        if ind['weight'] == 0:
            continue
        
        commentary = _get_indicator_commentary(ind['indicator'])
        
        summary.append({
            "indicator": ind['indicator'],
            "severity": _weight_to_severity(ind['weight']),
            "finding": ind['reason'],
            "analyst_comment": commentary,
            "weight": ind['weight'],
        })
    
    # Sort by weight descending
    summary.sort(key=lambda x: x['weight'], reverse=True)
    return summary


def _weight_to_severity(weight: int) -> str:
    """Convert weight to severity."""
    if weight >= 30:
        return "CRITICAL"
    elif weight >= 20:
        return "HIGH"
    elif weight >= 10:
        return "MEDIUM"
    else:
        return "LOW"


def _get_indicator_commentary(indicator: str) -> str:
    """Get analyst commentary for each indicator."""
    
    commentary_map = {
        'ip_in_url': 'Legitimate services rarely use IP addresses in URLs. This is a strong indicator of malicious intent.',
        'url_shortener': 'URL shorteners hide the destination, preventing users from assessing risk before clicking.',
        'credential_harvest': 'Email solicits sensitive information outside normal business processes. Classic phishing signature.',
        'urgency': 'Artificial time pressure reduces user deliberation and increases likelihood of mistakes.',
        'brand_mismatch': 'Domain name mimics a known brand but lacks official branding infrastructure.',
        'suspicious_keywords': 'Language patterns common in phishing campaigns detected.',
        'new_domain': 'Recently registered domains are frequently associated with phishing infrastructure.',
        'no_a_record': 'Domain cannot be resolved, indicating infrastructure issues or intentional masking.',
        'suspicious_tld': 'Top-level domain known for abuse and malicious registrations.',
        'free_sender': 'Sender using free email provider instead of organizational domain.',
        'sender_brand_mismatch': 'Sender domain does not match brands referenced in email body.',
        'suspicious_endpoint': 'URL endpoints commonly used in credential harvesting attacks.',
    }
    
    return commentary_map.get(indicator, 'Additional investigation recommended.')


def _generate_detection_rationale(indicators: List[Dict], score: int) -> str:
    """Explain the detection logic and scoring."""
    
    high_weight = len([i for i in indicators if i['weight'] >= 20])
    med_weight = len([i for i in indicators if 10 <= i['weight'] < 20])
    low_weight = len([i for i in indicators if 0 < i['weight'] < 10])
    
    rationale = f"""Detection Model Analysis:
- {high_weight} high-severity indicators (20+ points each)
- {med_weight} medium-severity indicators (10-20 points each)
- {low_weight} low-severity indicators (<10 points each)

Total aggregated risk score: {score}/100

The model combines multiple detection vectors including:
- Content analysis (keywords, urgency language)
- URL analysis (IP addresses, shorteners, suspicious endpoints)
- Sender analysis (domain legitimacy, free provider detection)
- Domain intelligence (registration age, DNS records, TLD reputation)"""
    
    return rationale.strip()


def _generate_remediation(threat_level: str, indicators: List[Dict], urls: List[str]) -> List[str]:
    """Generate remediation recommendations."""
    
    recommendations = []
    
    if threat_level in ["CRITICAL", "HIGH"]:
        recommendations.append("DO NOT CLICK any links in this email.")
        recommendations.append("DO NOT enter credentials or personal information on any website.")
        recommendations.append("Forward this email to your security team immediately.")
    
    if any(i['indicator'] == 'credential_harvest' for i in indicators):
        recommendations.append("If you already entered credentials, reset your password immediately from a trusted device.")
    
    if urls:
        recommendations.append(f"Block {len(urls)} malicious URL(s) at network perimeter if not already done.")
    
    if any(i['indicator'] == 'new_domain' for i in indicators):
        recommendations.append("Report malicious domain(s) to phishing databases (e.g., PhishTank, URLhaus).")
    
    if any(i['indicator'] == 'brand_mismatch' for i in indicators):
        recommendations.append("Verify sender identity through official company contact channels.")
    
    recommendations.append("Train recipients on phishing awareness and email security best practices.")
    
    if threat_level not in ["CRITICAL", "HIGH"]:
        recommendations.append("Monitor account for suspicious activity over next 30 days.")
    
    return recommendations


def format_report_for_display(report: Dict) -> str:
    """Format report for human-readable display."""
    
    output = f"""
╔══════════════════════════════════════════════════════════════╗
║           PHISHING ANALYZER - SOC ANALYST REPORT            ║
╚══════════════════════════════════════════════════════════════╝

THREAT LEVEL: [{report['threat_level']}] (Confidence: {report['confidence_percentage']}%)

EXECUTIVE SUMMARY
─────────────────
{report['executive_summary']}

THREAT ASSESSMENT
─────────────────
{report['threat_assessment']}

KEY INDICATORS
──────────────
"""
    
    for idx, ind in enumerate(report['key_indicators'], 1):
        output += f"\n{idx}. [{ind['severity']}] {ind['indicator'].replace('_', ' ').title()}\n"
        output += f"   Finding: {ind['finding']}\n"
        output += f"   Analysis: {ind['analyst_comment']}\n"
    
    output += f"\n\nDETECTION RATIONALE\n"
    output += "──────────────────\n"
    output += report['detection_rationale']
    
    output += f"\n\nREMEDIATION RECOMMENDATIONS\n"
    output += "──────────────────────────\n"
    for idx, rec in enumerate(report['remediation_recommendations'], 1):
        output += f"{idx}. {rec}\n"
    
    output += "\n" + "═" * 62 + "\n"
    
    return output
