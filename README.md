# Phishing Email Analyzer

A Python command-line tool for inspecting local `.eml` email files offline. It summarizes selected headers, extracts URLs without visiting them, lists attachment metadata, and reports basic suspicious indicators.

## Features

- Displays selected email headers, including `From`, `To`, `Reply-To`, and `Authentication-Results`.
- Extracts URLs without visiting or checking them online.
- Lists attachment metadata without opening or extracting attachments.
- Reports possible warning signs, such as:
  - Different sender and Reply-To domains
  - Urgency or account-verification language
  - Unencrypted `http://` URLs
  - Potentially risky attachment extensions
- Includes a synthetic sample email and unit tests.

## Requirements

- Python 3
- No third-party packages are required.

## Run the Analyzer

From the project folder, run:

```powershell
python email_analyzer.py samples/suspicious_sample.eml
```

## Run the Tests

```powershell
python -m unittest discover -v
```

The test suite contains four unit tests.

## Safety and Limitations

- The analyzer works with a local email file and does not visit extracted URLs.
- It lists attachment metadata only; it does not open or extract attachments.
- `Authentication-Results` is displayed as written in the email header. The analyzer does **not** independently verify SPF, DKIM, or DMARC.
- Suspicious indicators are warning signs, not proof that an email is phishing. No warnings do not guarantee an email is safe.
- The included sample email is synthetic and intended for testing.
- Only analyze emails you are authorized to inspect. Do not add real or private emails to this public project.
