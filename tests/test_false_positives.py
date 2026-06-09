import pytest
from app.analyzer import analyze_email


class TestLegitimateBusinessEmails:
    """
    Tests to ensure legitimate business emails are NOT flagged as phishing.
    Target: All legitimate business emails should score < 10.
    """

    def test_meeting_reminder(self):
        """Team meeting reminder should not be flagged."""
        email = """From: team@company.com
Subject: Team Meeting Reminder

Hi Team,

Just a reminder about our team meeting scheduled for tomorrow at 2 PM.
Please review the agenda in the attached document.

Thanks,
Manager"""
        result = analyze_email(email)
        assert result['score'] < 10, f"Meeting reminder scored {result['score']}, expected < 10"

    def test_project_update(self):
        """Project status update should not be flagged."""
        email = """From: manager@company.com
Subject: Project Updates

Hi Team,

Here are the latest project updates:

1. Q1 deliverables completed on schedule
2. Team is ready for Q2 kickoff
3. Project feedback from stakeholders is positive

Please update your status reports by Friday.

Best regards,
Project Manager"""
        result = analyze_email(email)
        assert result['score'] < 10, f"Project update scored {result['score']}, expected < 10"

    def test_weekly_status_report(self):
        """Weekly status report should not be flagged."""
        email = """From: report@company.com
Subject: Weekly Status Report

Team,

Please find the latest status report attached. This week's report includes:
- Team progress updates
- Schedule changes
- Feedback from the client

Please review and provide feedback by end of week.

Thanks"""
        result = analyze_email(email)
        assert result['score'] < 10, f"Status report scored {result['score']}, expected < 10"

    def test_calendar_reminder(self):
        """Calendar reminder should not be flagged."""
        email = """From: calendar@company.com
Subject: Calendar Reminder - Upcoming Meetings

You have the following calendar reminders:

1. Team meeting - Tomorrow 10:00 AM
2. Project kickoff - Next week 2:00 PM
3. Feedback session - Next week 3:00 PM

See you there!"""
        result = analyze_email(email)
        assert result['score'] < 10, f"Calendar reminder scored {result['score']}, expected < 10"

    def test_feedback_request(self):
        """Feedback request should not be flagged."""
        email = """From: hr@company.com
Subject: Team Feedback Request

Hi,

We would appreciate your feedback on the recent company changes.
Please share your thoughts and feedback in this survey.

This is a routine feedback collection, not a security matter.

Thanks,
HR Team"""
        result = analyze_email(email)
        assert result['score'] < 10, f"Feedback request scored {result['score']}, expected < 10"

    def test_conference_agenda(self):
        """Conference agenda should not be flagged."""
        email = """From: events@company.com
Subject: Annual Conference - Agenda

Hi Team,

The agenda for our annual conference is attached:

Day 1: Keynote speeches and team meetings
Day 2: Project updates and breakout sessions
Day 3: Feedback rounds and networking

Please review and let us know if you have questions.

Looking forward to seeing you there!"""
        result = analyze_email(email)
        assert result['score'] < 10, f"Conference agenda scored {result['score']}, expected < 10"

    def test_schedule_notification(self):
        """Schedule notification should not be flagged."""
        email = """From: scheduling@company.com
Subject: Schedule Update

Your schedule has been updated. Here are your upcoming meetings:

- Monday: Team standup at 9 AM
- Wednesday: Project review at 11 AM
- Friday: Feedback session at 3 PM

No action needed.

Scheduling System"""
        result = analyze_email(email)
        assert result['score'] < 10, f"Schedule notification scored {result['score']}, expected < 10"

    def test_quarterly_updates(self):
        """Quarterly business updates should not be flagged."""
        email = """From: communications@company.com
Subject: Q2 Business Updates

Team,

Here's a summary of Q2 updates:

1. Company performance: Strong growth
2. Team updates: New hires starting next month
3. Product updates: Version 2.0 launching soon

More details in the quarterly report.

Best regards,
Communications Team"""
        result = analyze_email(email)
        assert result['score'] < 10, f"Quarterly updates scored {result['score']}, expected < 10"

    def test_internal_announcement(self):
        """Internal company announcement should not be flagged."""
        email = """From: admin@company.com
Subject: Important Announcement

All,

Please take note of the following:

1. Office will be closed on Memorial Day
2. New parking schedule effective June 1st
3. Updated company guidelines in the attached PDF

No urgent action required. Update your calendars accordingly.

Admin Team"""
        result = analyze_email(email)
        assert result['score'] < 25, f"Internal announcement scored {result['score']}, expected < 25"


class TestPhishingDetectionWithContext:
    """
    Tests to ensure actual phishing emails are STILL detected correctly,
    even with the new context-aware filtering.
    """

    def test_verify_account_phishing(self):
        """Verify account phishing should still be detected."""
        email = """From: security@not-paypal.com
Subject: Urgent: Verify Your Account

Click here to verify your PayPal account immediately!

http://not-paypal.fake.com/verify"""
        result = analyze_email(email)
        assert result['score'] > 50, f"Phishing email scored {result['score']}, expected > 50"
        assert any(ind['indicator'] == 'suspicious_keywords' for ind in result['indicators']), "Should detect 'verify account' as phishing"

    def test_password_reset_phishing(self):
        """Password reset phishing should still be detected."""
        email = """From: admin@bank.fake.com
Subject: Reset Your Password

Your account needs immediate password reset.
Click the link below to reset your password now.

http://192.168.1.100/login"""
        result = analyze_email(email)
        assert result['score'] > 40, f"Password reset phishing scored {result['score']}, expected > 40"

    def test_credential_harvest_phishing(self):
        """Credential harvesting should still be detected."""
        email = """From: verify@amazon.fake.com
Subject: Confirm Your Amazon Account

We need to confirm your account information immediately.
Please enter your account number and password at the link below.

http://amazon.fake-domain.com/confirm"""
        result = analyze_email(email)
        assert result['score'] > 50, f"Credential harvest phishing scored {result['score']}, expected > 50"
        assert any(ind['indicator'] == 'credential_harvest' for ind in result['indicators']), "Should detect credential harvest"

    def test_urgency_phishing_combined(self):
        """Urgency language combined with other signals should still be detected."""
        email = """From: alerts@bank.fake.com
Subject: URGENT: Unusual Activity Detected

URGENT ACTION REQUIRED!

Unusual activity has been detected on your account.
You must act immediately to avoid suspension!

Click here now: http://192.168.1.50/verify"""
        result = analyze_email(email)
        assert result['score'] > 60, f"Urgency phishing scored {result['score']}, expected > 60"

    def test_update_in_phishing_context(self):
        """'Update' in phishing context (verify credentials) should be flagged."""
        email = """From: security@bank.fake.com
Subject: Important Security Update

Your account security update required.
Click to update your password immediately.

http://fake-bank.com/update-now"""
        result = analyze_email(email)
        # This should score higher because of IP/domain signals even if keywords are filtered
        assert result['score'] > 30, f"'Update' in phishing context scored {result['score']}, expected > 30"


class TestEdgeCases:
    """Test edge cases where legitimate and phishing signals overlap."""

    def test_legitimate_with_link(self):
        """Legitimate email with link but no phishing indicators."""
        email = """From: team@company.com
Subject: Team Meeting Agenda

Hi,

Our team meeting agenda is posted here: https://company.com/meetings/agenda

Looking forward to seeing you tomorrow!

Thanks,
Manager"""
        result = analyze_email(email)
        assert result['score'] < 15, f"Legitimate link scored {result['score']}, expected < 15"

    def test_phishing_with_shortener(self):
        """Phishing with URL shortener should still be detected."""
        email = """From: paypal@alert.fake.com
Subject: Verify Your Account

Please verify your account: http://bit.ly/abc123"""
        result = analyze_email(email)
        assert result['score'] > 30, f"Shortener phishing scored {result['score']}, expected > 30"

    def test_multiple_legitimate_keywords(self):
        """Multiple legitimate keywords should not accumulate to high score."""
        email = """From: manager@company.com
Subject: Team Meeting with Updates

Hi Team,

Our team meeting is scheduled for tomorrow. Here's the agenda and updates:

Agenda:
1. Project status updates
2. Team feedback session
3. Schedule updates for Q3
4. Reminder about upcoming deadline

Please review and provide feedback by Friday.

Thanks,
Manager"""
        result = analyze_email(email)
        assert result['score'] < 15, f"Multiple legitimate keywords scored {result['score']}, expected < 15"

    def test_legitimate_account_mention(self):
        """Mention of 'account' in legitimate context should not be flagged."""
        email = """From: finance@company.com
Subject: Account Information

Hi,

Here is your account information for the company expense tracking system:

Account ID: 12345
Project: Q2 Development
Team: Engineering

Please update your project settings in the system.

Thanks"""
        result = analyze_email(email)
        assert result['score'] < 10, f"Account mention in legitimate context scored {result['score']}, expected < 10"
