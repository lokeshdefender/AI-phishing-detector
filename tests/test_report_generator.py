import pytest
from app.report_generator import (
    generate_analyst_report,
    _get_threat_level,
    _weight_to_severity,
)


def test_threat_level_mapping():
    """Test threat level classification."""
    assert _get_threat_level(95) == "CRITICAL"
    assert _get_threat_level(75) == "HIGH"
    assert _get_threat_level(50) == "MEDIUM"
    assert _get_threat_level(25) == "LOW"
    assert _get_threat_level(10) == "MINIMAL"


def test_severity_mapping():
    """Test severity classification."""
    assert _weight_to_severity(35) == "CRITICAL"
    assert _weight_to_severity(25) == "HIGH"
    assert _weight_to_severity(15) == "MEDIUM"
    assert _weight_to_severity(5) == "LOW"


def test_generate_report_high_threat():
    """Test report generation for high-threat email."""
    indicators = [
        {"indicator": "credential_harvest", "reason": "Password requested", "weight": 50},
        {"indicator": "urgency", "reason": "Time pressure applied", "weight": 20},
        {"indicator": "ip_in_url", "reason": "IP address in URL", "weight": 30},
    ]
    
    report = generate_analyst_report(
        score=85,
        indicators=indicators,
        urls=["http://192.168.1.1/login"],
        sender="attacker@fake.com",
        email_text="Enter password now!"
    )
    
    assert report['threat_level'] == "CRITICAL"
    assert "DO NOT CLICK" in str(report['remediation_recommendations'])
    assert len(report['key_indicators']) == 3
    assert report['threat_level'] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]


def test_generate_report_low_threat():
    """Test report generation for low-threat email."""
    indicators = [
        {"indicator": "suspicious_keywords", "reason": "Verify found", "weight": 8},
    ]
    
    report = generate_analyst_report(
        score=15,
        indicators=indicators,
        urls=["https://example.com"],
        sender="info@legitimate.com",
        email_text="Please verify your email"
    )
    
    assert report['threat_level'] == "MINIMAL"
    assert "DO NOT CLICK" not in str(report['remediation_recommendations'])


def test_report_has_all_required_fields():
    """Test report contains all required fields."""
    indicators = [
        {"indicator": "urgency", "reason": "Time pressure", "weight": 20},
    ]
    
    report = generate_analyst_report(
        score=50,
        indicators=indicators,
        urls=[],
        sender="unknown@test.com",
        email_text="Act now!"
    )
    
    assert 'threat_level' in report
    assert 'executive_summary' in report
    assert 'threat_assessment' in report
    assert 'key_indicators' in report
    assert 'detection_rationale' in report
    assert 'remediation_recommendations' in report
    assert 'confidence_percentage' in report
    assert isinstance(report['remediation_recommendations'], list)
    assert len(report['remediation_recommendations']) > 0


def test_remediation_escalates_with_threat():
    """Test that remediation is more urgent for high threats."""
    high_threat_report = generate_analyst_report(
        score=90,
        indicators=[{"indicator": "credential_harvest", "reason": "Creds requested", "weight": 50}],
        urls=["http://fake.com/login"],
        sender="attacker@evil.com",
        email_text="Enter credentials now!"
    )
    
    low_threat_report = generate_analyst_report(
        score=15,
        indicators=[],
        urls=[],
        sender="info@legitimate.com",
        email_text="Normal email"
    )
    
    # High threat should have urgent recommendations
    high_recs_str = str(high_threat_report['remediation_recommendations'])
    assert "security team" in high_recs_str or "CRITICAL" in high_threat_report['threat_level']
    
    # Low threat should have fewer urgent recommendations
    assert len(low_threat_report['remediation_recommendations']) < len(high_threat_report['remediation_recommendations'])
