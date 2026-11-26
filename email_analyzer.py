"""Offline parser for a local .eml email file."""

import argparse
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path


URL_PATTERN = re.compile(
    r"""https?://[^\s<>"']+""",
    re.IGNORECASE,
)


def get_email_address(value):
    """Return the email address from a header, if present."""
    if not value:
        return None

    address = parseaddr(str(value))[1].strip()
    return address.casefold() if address else None


def extract_urls(text):
    """Find URLs in text without opening or visiting them."""
    urls = set()

    for match in URL_PATTERN.findall(text):
        url = match.rstrip(".,;:!?)]}")
        if url:
            urls.add(url)

    return sorted(urls)


def extract_body_text(message):
    """Read plain-text and HTML body parts, but skip attachments."""
    body_parts = []

    for part in message.walk():
        if part.is_multipart():
            continue

        if part.get_content_disposition() == "attachment":
            continue

        if part.get_content_type() not in ("text/plain", "text/html"):
            continue

        try:
            content = part.get_content()
        except (LookupError, UnicodeError, TypeError):
            continue

        if isinstance(content, str):
            body_parts.append(content)

    return "\n".join(body_parts)


def extract_attachment_metadata(message):
    """List attachment names and types without opening the attachments."""
    attachments = []

    for part in message.walk():
        filename = part.get_filename()
        disposition = part.get_content_disposition()

        if filename or disposition == "attachment":
            attachments.append(
                {
                    "filename": filename or "(filename not provided)",
                    "content_type": part.get_content_type(),
                }
            )

    return attachments


def inspect_email(file_path):
    """Parse a local .eml file and return basic email information."""
    path = Path(file_path)

    if path.suffix.casefold() != ".eml":
        raise ValueError("Input file must have a .eml extension.")

    if not path.is_file():
        raise FileNotFoundError(f"Email file not found: {path}")

    message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    body_text = extract_body_text(message)

    indicators = []

    sender = get_email_address(message.get("From", ""))
    reply_to = get_email_address(message.get("Reply-To", ""))
    subject = str(message.get("Subject", ""))
    urls = extract_urls(body_text)
    attachments = extract_attachment_metadata(message)

    if sender and reply_to and "@" in sender and "@" in reply_to:
        sender_domain = sender.rsplit("@", 1)[-1].casefold()
        reply_domain = reply_to.rsplit("@", 1)[-1].casefold()
        if sender_domain != reply_domain:
            indicators.append("Sender and Reply-To use different domains")

    urgency_terms = (
        "urgent",
        "verify",
        "immediately",
        "suspended",
        "action required",
    )
    if any(term in subject.casefold() for term in urgency_terms):
        indicators.append("Subject contains urgency or account-verification language")

    if any(url.casefold().startswith("http://") for url in urls):
        indicators.append("Email contains an unencrypted HTTP URL")

    risky_extensions = {".html", ".htm", ".exe", ".js", ".vbs", ".scr"}
    for attachment in attachments:
        filename = attachment.get("filename", "")
        if Path(filename).suffix.casefold() in risky_extensions:
            indicators.append(
                f"Attachment has a potentially risky extension: {filename}"
            )

    return {
        "file": path.name,
        "from": get_email_address(message.get("From")),
        "to": str(message.get("To", "Not provided")),
        "reply_to": get_email_address(message.get("Reply-To")),
        "subject": str(message.get("Subject", "No subject")),
        "authentication_results": [
            str(value)
            for value in message.get_all("Authentication-Results", [])
        ],
                "urls": urls,
        "attachments": attachments,
        "indicators": indicators,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Inspect a local .eml file without opening links or attachments."
    )
    parser.add_argument(
        "email_file",
        type=Path,
        help="Path to a local .eml file",
    )
    args = parser.parse_args()

    try:
        report = inspect_email(args.email_file)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print("=== Offline Email Inspection ===")
    print(f"File: {report['file']}")
    print(f"From: {report['from'] or 'Not found'}")
    print(f"To: {report['to']}")
    print(f"Reply-To: {report['reply_to'] or 'Not provided'}")
    print(f"Subject: {report['subject']}")

    print("\nAuthentication-Results header (not independently verified):")
    if report["authentication_results"]:
        for result in report["authentication_results"]:
            print(f"  - {result}")
    else:
        print("  - Not provided")

    print("\nURLs found (not opened or checked online):")
    if report["urls"]:
        for url in report["urls"]:
            print(f"  - {url}")
    else:
        print("  - None found")

    print("\nAttachments (metadata only; not opened or extracted):")
    if report["attachments"]:
        for attachment in report["attachments"]:
            print(
                f"  - {attachment['filename']} "
                f"({attachment['content_type']})"
            )
    else:
        print("  - None found")
        
    print("\nPotentially suspicious indicators (not proof of phishing):")
    if report["indicators"]:
        for indicator in report["indicators"]:
            print(f"- {indicator}")
    else:
        print("- No indicators detected by these basic checks.")

if __name__ == "__main__":
    main()