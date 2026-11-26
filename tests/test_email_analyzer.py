import unittest
from pathlib import Path

from email_analyzer import inspect_email


SAMPLE_EMAIL = (
    Path(__file__).resolve().parents[1]
    / "samples"
    / "suspicious_sample.eml"
)


class TestEmailAnalyzer(unittest.TestCase):
    def test_sample_extracts_url_and_attachment_metadata(self):
        report = inspect_email(SAMPLE_EMAIL)

        self.assertEqual(report["file"], "suspicious_sample.eml")
        self.assertIn(
            "http://payroll-example.invalid/verify",
            report["urls"],
        )

        attachment_names = [
            attachment["filename"]
            for attachment in report["attachments"]
        ]
        self.assertIn("payroll_update.html", attachment_names)

    def test_sample_reports_suspicious_indicators(self):
        report = inspect_email(SAMPLE_EMAIL)
        indicators = report["indicators"]

        self.assertTrue(any("different domains" in item for item in indicators))
        self.assertTrue(any("urgency" in item for item in indicators))
        self.assertTrue(any("unencrypted HTTP URL" in item for item in indicators))
        self.assertTrue(any("risky extension" in item for item in indicators))

    def test_rejects_file_without_eml_extension(self):
        with self.assertRaises(ValueError):
            inspect_email("not_an_email.txt")

    def test_missing_eml_file_raises_error(self):
        missing_email = Path(__file__).resolve().parent / "missing_sample.eml"

        with self.assertRaises(FileNotFoundError):
            inspect_email(missing_email)