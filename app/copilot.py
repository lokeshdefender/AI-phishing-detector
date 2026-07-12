import json
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from . import database as database_module
from .investigation_graph import parse_cached_graph
from .mitre_mapping import parse_cached_mitre
from .models_db import Investigation, ThreatIntelIndicator


QUICK_ACTIONS = {
    "summarize_investigation": "Summarize the investigation.",
    "explain_risk_score": "Explain risk score.",
    "explain_virustotal_findings": "Explain VirusTotal findings.",
    "list_all_iocs": "List all IOCs.",
    "suggest_containment_actions": "Suggest containment actions.",
    "suggest_remediation_steps": "Suggest remediation steps.",
    "generate_executive_summary": "Generate executive summary.",
    "generate_technical_summary": "Generate technical summary.",
}


def _safe_json(value: Any, fallback: Any) -> Any:
    if value is None:
        return fallback
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return fallback
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return fallback
    return fallback


def build_investigation_context(session: Session, investigation: Investigation) -> Dict[str, Any]:
    indicators = (
        session.query(ThreatIntelIndicator)
        .filter(ThreatIntelIndicator.investigation_id == investigation.id)
        .order_by(ThreatIntelIndicator.risk_score.desc(), ThreatIntelIndicator.created_at.desc())
        .all()
    )

    threat_intel = []
    for ind in indicators:
        threat_intel.append(
            {
                "ioc_value": ind.ioc_value,
                "ioc_type": ind.ioc_type,
                "risk_score": ind.risk_score,
                "confidence": ind.confidence,
                "reputation": ind.reputation,
                "detection_summary": ind.detection_summary or "",
                "source_providers": _safe_json(ind.source_providers, []),
                "provider_results": _safe_json(ind.provider_responses, {}),
            }
        )

    timeline = database_module.get_timeline_events(investigation.id, order="asc", limit=200)
    graph = parse_cached_graph(investigation.graph) or {"nodes": [], "edges": [], "metadata": {}}

    report = _safe_json(investigation.analyst_report, {})
    executive_summary = investigation.summary or report.get("executive_summary") or report.get("summary") or ""

    all_iocs = []
    seen = set()

    def add_ioc(value: str, ioc_type: str) -> None:
        candidate = (value or "").strip()
        if not candidate:
            return
        key = (ioc_type, candidate.lower())
        if key in seen:
            return
        seen.add(key)
        all_iocs.append({"value": candidate, "type": ioc_type})

    for item in _safe_json(investigation.evidence, []):
        add_ioc(str(item), "Evidence")

    for item in _safe_json(investigation.urls, []):
        add_ioc(str(item), "URL")

    for ti in threat_intel:
        add_ioc(ti["ioc_value"], ti["ioc_type"])

    return {
        "case_id": investigation.case_id,
        "status": investigation.status or "Open",
        "risk_score": int(investigation.phishing_score or 0),
        "confidence": int(investigation.confidence or 0),
        "threat_level": investigation.threat_level or "MINIMAL",
        "executive_summary": executive_summary,
        "analyst_notes": investigation.analyst_notes or "",
        "timeline": timeline,
        "graph": graph,
        "mitre": parse_cached_mitre(investigation.mitre_mappings) or {"mappings": [], "metadata": {}},
        "threat_intel": threat_intel,
        "iocs": all_iocs,
        "report": report,
    }


def _find_most_dangerous_ioc(context: Dict[str, Any]) -> Dict[str, Any] | None:
    threat_intel = context.get("threat_intel") or []
    if not threat_intel:
        return None
    return max(threat_intel, key=lambda item: int(item.get("risk_score") or 0))


def _collect_virustotal_findings(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    for item in context.get("threat_intel") or []:
        provider_results = item.get("provider_results") or {}
        vt = provider_results.get("VirusTotal")
        if not isinstance(vt, dict):
            continue
        findings.append(
            {
                "ioc_value": item.get("ioc_value"),
                "ioc_type": item.get("ioc_type"),
                "status": vt.get("status"),
                "data": vt.get("data", {}) if isinstance(vt.get("data"), dict) else {},
                "details": vt.get("details") or "",
            }
        )
    return findings


def _response_with_evidence(body: str, evidence: List[str]) -> str:
    if evidence:
        return body + "\n\nEvidence:\n- " + "\n- ".join(evidence)
    return body + "\n\nEvidence: Investigation data does not contain enough supporting details for this request."


def _executive_summary(context: Dict[str, Any]) -> str:
    if context.get("executive_summary"):
        return str(context["executive_summary"])

    dangerous = _find_most_dangerous_ioc(context)
    if dangerous:
        return (
            f"Case {context['case_id']} is currently {context['status']} with threat level {context['threat_level']} "
            f"and risk score {context['risk_score']}/100. Highest-risk indicator is {dangerous.get('ioc_type')} "
            f"{dangerous.get('ioc_value')} at risk {dangerous.get('risk_score')}/100."
        )

    return (
        f"Case {context['case_id']} is currently {context['status']} with threat level {context['threat_level']} "
        f"and risk score {context['risk_score']}/100. No enriched IOC risk records are available yet."
    )


def _technical_summary(context: Dict[str, Any]) -> str:
    lines = [
        f"Case: {context['case_id']}",
        f"Status: {context['status']}",
        f"Risk score: {context['risk_score']}/100",
        f"Confidence: {context['confidence']}/100",
        f"Threat level: {context['threat_level']}",
        f"Timeline events: {len(context.get('timeline') or [])}",
        f"Graph nodes: {len((context.get('graph') or {}).get('nodes') or [])}",
        f"Graph edges: {len((context.get('graph') or {}).get('edges') or [])}",
        f"Threat intel entries: {len(context.get('threat_intel') or [])}",
    ]

    dangerous = _find_most_dangerous_ioc(context)
    if dangerous:
        lines.append(
            f"Top IOC: {dangerous.get('ioc_type')} {dangerous.get('ioc_value')} (risk {dangerous.get('risk_score')}/100)."
        )

    return "\n".join(lines)


def _suggest_containment(context: Dict[str, Any]) -> str:
    dangerous = _find_most_dangerous_ioc(context)
    actions = []
    if dangerous:
        dtype = (dangerous.get("ioc_type") or "").lower()
        ioc_value = dangerous.get("ioc_value")
        if "url" in dtype or "domain" in dtype:
            actions.append(f"Block outbound traffic to {ioc_value} at web proxy and DNS layers.")
        if "ip" in dtype:
            actions.append(f"Block network communications to {ioc_value} at firewall and EDR policy layers.")
        if "file hash" in dtype:
            actions.append(f"Block and quarantine artifacts matching hash {ioc_value} on endpoints.")

    actions.append("Search SIEM and endpoint telemetry for related indicators and affected users.")
    actions.append("Preserve relevant email, host, and network logs for incident response evidence.")

    return "\n".join(f"- {item}" for item in actions)


def _suggest_remediation(context: Dict[str, Any]) -> str:
    actions = [
        "- Reset potentially exposed credentials and invalidate active sessions.",
        "- Review mailbox and endpoint for persistence indicators tied to this case.",
        "- Remove malicious messages/URLs from user access paths.",
        "- Update detections and blocklists with validated case indicators.",
    ]
    if not context.get("threat_intel"):
        actions.append("- Threat intelligence data is limited; complete enrichment before final remediation closure.")
    return "\n".join(actions)


def _mitre_mappings(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    mitre = context.get("mitre") or {}
    mappings = mitre.get("mappings") if isinstance(mitre, dict) else []
    return mappings if isinstance(mappings, list) else []


def _mitre_defensive_actions(mappings: List[Dict[str, Any]]) -> List[str]:
    actions = []
    tactics = {str(item.get("tactic") or "").lower() for item in mappings}

    if "initial access" in tactics:
        actions.append("Harden email filtering and URL detonation policies for inbound phishing controls.")
        actions.append("Enforce user verification for login/reset requests arriving via email links.")
    if "credential access" in tactics:
        actions.append("Reset potentially exposed credentials and enforce MFA re-registration where needed.")
        actions.append("Monitor authentication logs for suspicious sign-in patterns tied to this case.")
    if "command and control" in tactics:
        actions.append("Block suspected C2 domains/IPs at proxy, DNS, and firewall control points.")
        actions.append("Inspect outbound web traffic for recurring beacon-like activity.")
    if "execution" in tactics:
        actions.append("Quarantine suspected malicious files and enforce attachment execution restrictions.")
    if "persistence" in tactics:
        actions.append("Audit startup entries, scheduled tasks, and run keys on impacted hosts.")

    if not actions:
        actions.append("No ATT&CK mappings are currently available to derive tactic-specific defensive actions.")
    return actions


def generate_copilot_response(context: Dict[str, Any], user_message: str, *, quick_action: str | None = None) -> str:
    prompt = (quick_action or user_message or "").strip().lower()

    most_dangerous = _find_most_dangerous_ioc(context)
    vt_findings = _collect_virustotal_findings(context)
    mitre = _mitre_mappings(context)

    if quick_action == "summarize_investigation" or "summarize" in prompt:
        body = _executive_summary(context)
        return _response_with_evidence(body, [f"status={context['status']}", f"risk_score={context['risk_score']}", f"timeline_events={len(context.get('timeline') or [])}"])

    if quick_action == "explain_risk_score" or "risk" in prompt:
        reasons = [f"Current risk score is {context['risk_score']}/100 with confidence {context['confidence']}/100."]
        if most_dangerous:
            reasons.append(
                f"Highest IOC risk is {most_dangerous.get('ioc_type')} {most_dangerous.get('ioc_value')} at {most_dangerous.get('risk_score')}/100."
            )
        else:
            reasons.append("No enriched IOC risk entries are stored yet, so risk explanation is limited to case-level score.")
        return _response_with_evidence(" ".join(reasons), [
            f"threat_level={context['threat_level']}",
            f"top_ioc={most_dangerous.get('ioc_value')}" if most_dangerous else "top_ioc=unavailable",
        ])

    if quick_action == "explain_virustotal_findings" or "virustotal" in prompt:
        if not vt_findings:
            return _response_with_evidence(
                "VirusTotal findings are unavailable for this investigation. The stored threat intelligence data does not include VirusTotal provider results.",
                [],
            )
        lines = []
        evidence = []
        for finding in vt_findings[:10]:
            data = finding.get("data") or {}
            lines.append(
                f"{finding.get('ioc_type')} {finding.get('ioc_value')}: status={finding.get('status')}, "
                f"malicious={data.get('malicious', 'n/a')}, suspicious={data.get('suspicious', 'n/a')}, harmless={data.get('harmless', 'n/a')}"
            )
            evidence.append(f"vt:{finding.get('ioc_value')}:{finding.get('status')}")
        return _response_with_evidence("\n".join(lines), evidence)

    if quick_action == "list_all_iocs" or "list" in prompt and "ioc" in prompt:
        iocs = context.get("iocs") or []
        if not iocs:
            return _response_with_evidence("No IOCs are currently stored for this investigation.", [])
        lines = [f"{item.get('type')}: {item.get('value')}" for item in iocs]
        return _response_with_evidence("\n".join(lines), [f"ioc_count={len(iocs)}"])

    if quick_action == "suggest_containment_actions" or "containment" in prompt:
        return _response_with_evidence(_suggest_containment(context), [f"status={context['status']}", f"risk_score={context['risk_score']}"])

    if quick_action == "suggest_remediation_steps" or "remediation" in prompt:
        return _response_with_evidence(_suggest_remediation(context), [f"threat_level={context['threat_level']}"])

    if quick_action == "generate_executive_summary" or "executive summary" in prompt:
        return _response_with_evidence(_executive_summary(context), [f"case_id={context['case_id']}", f"status={context['status']}" ])

    if quick_action == "generate_technical_summary" or "technical summary" in prompt:
        return _response_with_evidence(_technical_summary(context), [f"threat_intel_entries={len(context.get('threat_intel') or [])}"])

    if "defensive actions" in prompt and ("mitre" in prompt or "att&ck" in prompt or "tactic" in prompt):
        actions = _mitre_defensive_actions(mitre)
        return _response_with_evidence(
            "Recommended defensive actions based on current ATT&CK mappings:\n" + "\n".join(f"- {a}" for a in actions),
            [f"mitre_mappings={len(mitre)}"],
        )

    if "att&ck" in prompt or "mitre" in prompt or "technique" in prompt or "tactic" in prompt:
        if not mitre:
            return _response_with_evidence(
                "No MITRE ATT&CK techniques are mapped for this investigation yet. Stored evidence is currently insufficient for confident technique mapping.",
                [],
            )
        lines = []
        evidence = []
        for item in mitre:
            lines.append(
                f"{item.get('attack_id')} - {item.get('technique')} ({item.get('tactic')}) confidence {item.get('confidence')}/100"
            )
            reason = item.get("explanation") or ""
            if reason:
                lines.append(f"  Why selected: {reason}")
            for ev in (item.get("evidence") or [])[:3]:
                lines.append(f"  Evidence: {ev}")
            evidence.append(f"{item.get('attack_id')}:{item.get('confidence')}")
        return _response_with_evidence("\n".join(lines), evidence)

    if "most dangerous" in prompt:
        if not most_dangerous:
            return _response_with_evidence("Unable to identify a most dangerous IOC because no enriched IOC risk entries are stored for this case.", [])
        body = (
            f"Most dangerous IOC is {most_dangerous.get('ioc_type')} {most_dangerous.get('ioc_value')} "
            f"with risk score {most_dangerous.get('risk_score')}/100 and confidence {most_dangerous.get('confidence')}/100."
        )
        return _response_with_evidence(body, [f"ioc={most_dangerous.get('ioc_value')}", f"risk={most_dangerous.get('risk_score')}" ])

    if "evidence" in prompt:
        pieces = []
        if context.get("timeline"):
            pieces.append(f"Timeline events: {len(context['timeline'])}")
        if context.get("threat_intel"):
            pieces.append(f"Threat intel records: {len(context['threat_intel'])}")
        if (context.get("graph") or {}).get("nodes"):
            pieces.append(f"Graph nodes: {len(context['graph']['nodes'])}")
        if context.get("analyst_notes"):
            pieces.append("Analyst notes are present")
        if not pieces:
            return _response_with_evidence("Stored investigation evidence is currently limited; no timeline/intel/graph artifacts were found.", [])
        return _response_with_evidence("Evidence supporting this case includes: " + "; ".join(pieces), pieces)

    if "soc analyst" in prompt or "what should" in prompt or "next" in prompt:
        body = "Recommended next SOC actions based on current case data:\n" + _suggest_containment(context) + "\n" + _suggest_remediation(context)
        return _response_with_evidence(body, [f"status={context['status']}", f"risk_score={context['risk_score']}"])

    return _response_with_evidence(
        "This copilot is investigation-scoped and grounded in stored case data only. Rephrase your request toward available context such as summary, timeline, graph, threat intel, VirusTotal, IOC list, risk, containment, or remediation.",
        [
            f"timeline_events={len(context.get('timeline') or [])}",
            f"threat_intel_entries={len(context.get('threat_intel') or [])}",
            f"graph_nodes={len((context.get('graph') or {}).get('nodes') or [])}",
        ],
    )
