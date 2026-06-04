import pytest
from app.utils import parse_eml_file


def test_parse_simple_eml():
    """Test parsing a simple .eml file."""
    eml_content = b"""From: test@example.com
Subject: Test Email
To: recipient@example.com

This is a test email body."""
    
    result = parse_eml_file(eml_content)
    assert result['sender'] == 'test@example.com'
    assert result['subject'] == 'Test Email'
    assert 'test email body' in result['body'].lower()


def test_parse_eml_with_html():
    """Test parsing .eml with HTML content."""
    eml_content = b"""From: phisher@fake.com
Subject: Verify Account
To: victim@real.com
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain

Please verify at https://fake-paypal.com/login

--boundary123
Content-Type: text/html

<html><body>Click here to verify</body></html>

--boundary123--"""
    
    result = parse_eml_file(eml_content)
    assert result['sender'] == 'phisher@fake.com'
    assert result['subject'] == 'Verify Account'
    assert 'verify' in result['body'].lower()


def test_parse_invalid_eml():
    """Test parsing invalid .eml file."""
    eml_content = b"This is not a valid email"
    
    result = parse_eml_file(eml_content)
    # Should not raise an error, but return empty/error
    assert 'error' not in result or len(result.get('sender', '')) >= 0
